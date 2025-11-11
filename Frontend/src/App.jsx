import React, { useState, useEffect } from 'react';
import API from './api';
import GoalItem from './components/GoalItem';
import './App.css';

export default function App() {
  const [goals, setGoals] = useState([]);
  const [text, setText] = useState('');

  useEffect(() => { fetchGoals(); }, []);

  async function fetchGoals() {
    const res = await API.get('/goals');
    setGoals(res.data);
  }

  async function addGoal(e) {
    e.preventDefault();
    if (!text.trim()) return;
    await API.post('/goals', { text });
    setText('');
    fetchGoals();
  }

  async function toggle(id) {
    await API.patch(`/goals/${id}/toggle`);
    fetchGoals();
  }

  return (
    <div className="app-container">
      <h1 className="app-title">🎯 Goal Tracker</h1>

      <form onSubmit={addGoal} className="goal-form">
        <input
          className="goal-input"
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Add your goal..."
        />
        <button className="goal-button" type="submit">Add</button>
      </form>

      <div className="goal-list">
        {goals.length === 0 ? (
          <p className="empty-text">No goals yet. Add one above!</p>
        ) : (
          goals.map(g => (
            <GoalItem key={g._id} goal={g} onToggle={toggle} />
          ))
        )}
      </div>
    </div>
  );
}
