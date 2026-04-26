const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const SECRET = 'troque-esta-chave-em-producao';
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./crm.db');
const run = (sql, params=[]) => new Promise((res, rej)=>db.run(sql, params, function(e){e?rej(e):res(this)}));
const all = (sql, params=[]) => new Promise((res, rej)=>db.all(sql, params, (e,r)=>e?rej(e):res(r)));
const get = (sql, params=[]) => new Promise((res, rej)=>db.get(sql, params, (e,r)=>e?rej(e):res(r)));

async function init(){
 await run(`CREATE TABLE IF NOT EXISTS usuarios(id INTEGER PRIMARY KEY AUTOINCREMENT,nome TEXT,email TEXT UNIQUE,senha TEXT,tipo TEXT)`);
 await run(`CREATE TABLE IF NOT EXISTS clientes(id INTEGER PRIMARY KEY AUTOINCREMENT,nome TEXT,data_nascimento TEXT,cpf TEXT,rg TEXT,telefone TEXT,email TEXT,endereco TEXT,vendedor_id INTEGER,observacoes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
 await run(`CREATE TABLE IF NOT EXISTS produtos_cliente(id INTEGER PRIMARY KEY AUTOINCREMENT,cliente_id INTEGER,ambiente TEXT,valor REAL,status TEXT,observacoes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
 await run(`CREATE TABLE IF NOT EXISTS lembretes(id INTEGER PRIMARY KEY AUTOINCREMENT,cliente_id INTEGER,tipo TEXT,data TEXT,mensagem TEXT,status TEXT DEFAULT 'pendente')`);
 const admin = await get('SELECT id FROM usuarios WHERE email=?',['admin@empresa.com']);
 if(!admin){ await run('INSERT INTO usuarios(nome,email,senha,tipo) VALUES(?,?,?,?)',['Administrador','admin@empresa.com',bcrypt.hashSync('123456',10),'admin']); }
}
init();

function auth(req,res,next){
 const token = (req.headers.authorization||'').replace('Bearer ', '');
 if(!token) return res.status(401).json({erro:'Token ausente'});
 try{ req.user = jwt.verify(token, SECRET); next(); }catch{ res.status(401).json({erro:'Token inválido'}); }
}

app.post('/login', async (req,res)=>{
 const {email, senha} = req.body;
 const user = await get('SELECT * FROM usuarios WHERE email=?',[email]);
 if(!user || !bcrypt.compareSync(senha, user.senha)) return res.status(401).json({erro:'Login inválido'});
 const token = jwt.sign({id:user.id,nome:user.nome,tipo:user.tipo}, SECRET, {expiresIn:'8h'});
 res.json({token, usuario:{id:user.id,nome:user.nome,tipo:user.tipo}});
});

app.post('/usuarios', auth, async (req,res)=>{
 if(req.user.tipo !== 'admin') return res.status(403).json({erro:'Apenas admin'});
 const {nome,email,senha,tipo='vendedor'} = req.body;
 const r = await run('INSERT INTO usuarios(nome,email,senha,tipo) VALUES(?,?,?,?)',[nome,email,bcrypt.hashSync(senha,10),tipo]);
 res.json({id:r.lastID,nome,email,tipo});
});

app.get('/usuarios', auth, async (req,res)=>{
 if(req.user.tipo !== 'admin') return res.status(403).json({erro:'Apenas admin'});
 res.json(await all('SELECT id,nome,email,tipo FROM usuarios ORDER BY nome'));
});

app.post('/clientes', auth, async (req,res)=>{
 const c = req.body;
 const vendedor = req.user.tipo === 'admin' ? c.vendedor_id : req.user.id;
 const r = await run(`INSERT INTO clientes(nome,data_nascimento,cpf,rg,telefone,email,endereco,vendedor_id,observacoes) VALUES(?,?,?,?,?,?,?,?,?)`,[c.nome,c.data_nascimento,c.cpf,c.rg,c.telefone,c.email,c.endereco,vendedor,c.observacoes]);
 res.json({id:r.lastID});
});

app.get('/clientes', auth, async (req,res)=>{
 const where = req.user.tipo === 'admin' ? '' : 'WHERE c.vendedor_id=?';
 const params = req.user.tipo === 'admin' ? [] : [req.user.id];
 res.json(await all(`SELECT c.*, u.nome vendedor_nome, COALESCE(SUM(p.valor),0) ticket_total FROM clientes c LEFT JOIN usuarios u ON u.id=c.vendedor_id LEFT JOIN produtos_cliente p ON p.cliente_id=c.id ${where} GROUP BY c.id ORDER BY c.created_at DESC`, params));
});

app.post('/clientes/:id/produtos', auth, async (req,res)=>{
 const {ambiente,valor,status='orçamento',observacoes} = req.body;
 const r = await run('INSERT INTO produtos_cliente(cliente_id,ambiente,valor,status,observacoes) VALUES(?,?,?,?,?)',[req.params.id,ambiente,valor,status,observacoes]);
 res.json({id:r.lastID});
});

app.get('/clientes/:id/produtos', auth, async (req,res)=>{
 res.json(await all('SELECT * FROM produtos_cliente WHERE cliente_id=? ORDER BY created_at DESC',[req.params.id]));
});

app.get('/aniversariantes/hoje', auth, async (req,res)=>{
 const hoje = new Date();
 const mmdd = String(hoje.getMonth()+1).padStart(2,'0')+'-'+String(hoje.getDate()).padStart(2,'0');
 const where = req.user.tipo === 'admin' ? '' : 'AND vendedor_id=?';
 const params = req.user.tipo === 'admin' ? [mmdd] : [mmdd, req.user.id];
 const clientes = await all(`SELECT * FROM clientes WHERE substr(data_nascimento,6,5)=? ${where}`, params);
 res.json(clientes.map(c=>({...c, mensagem:`Olá, ${c.nome}! Hoje é um dia muito especial e queremos te desejar um feliz aniversário, com muita saúde, alegria e realizações. Que seu novo ciclo seja incrível! 🎉`})));
});

app.get('/relatorios/vendedores', auth, async (req,res)=>{
 if(req.user.tipo !== 'admin') return res.status(403).json({erro:'Apenas admin'});
 res.json(await all(`SELECT u.nome vendedor, COUNT(DISTINCT c.id) clientes, COALESCE(SUM(p.valor),0) total_orcado FROM usuarios u LEFT JOIN clientes c ON c.vendedor_id=u.id LEFT JOIN produtos_cliente p ON p.cliente_id=c.id WHERE u.tipo='vendedor' GROUP BY u.id ORDER BY total_orcado DESC`));
});

app.listen(3001, ()=>console.log('CRM rodando em http://localhost:3001'));
