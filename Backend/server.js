// Minimal in-memory backend for Goal Tracker (no DB)
// Run: npm install && npm start

const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');

const app = express();
app.use(cors()); // allow all origins in dev
app.use(express.json());

const PORT = process.env.PORT || 4000;

// In-memory store
let goals = []; // each item: { _id, text, done (bool), createdAt }

// Health
app.get('/', (req, res) => res.json({ ok: true }));

// GET /goals -> return goals newest first
app.get('/goals', (req, res) => {
  // return a shallow copy sorted by createdAt desc
  const list = [...goals].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

// POST /goals -> create new goal { text }
app.post('/goals', (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.toString().trim()) {
      return res.status(400).json({ error: 'Text is required' });
    }
    const item = {
      _id: randomUUID(),
      text: text.toString().trim(),
      done: false,
      createdAt: new Date().toISOString()
    };
    goals.push(item);
    res.status(201).json(item);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /goals/:id/toggle -> toggle done
app.patch('/goals/:id/toggle', (req, res) => {
  try {
    const id = req.params.id;
    const idx = goals.findIndex(g => g._id === id);
    if (idx === -1) return res.status(404).json({ error: 'Goal not found' });
    goals[idx].done = !goals[idx].done;
    res.json(goals[idx]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Optional: delete (not required by your frontend but handy)
app.delete('/goals/:id', (req, res) => {
  const id = req.params.id;
  const prevLength = goals.length;
  goals = goals.filter(g => g._id !== id);
  if (goals.length === prevLength) return res.status(404).json({ error: 'Goal not found' });
  res.status(204).send();
});

app.listen(PORT, () => console.log(`In-memory server listening on http://localhost:${PORT}`));
