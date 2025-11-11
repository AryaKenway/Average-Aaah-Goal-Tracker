import React from 'react';

export default function GoalItem({ goal, onToggle }) {
  return (
    <div className="goal-item">
      <input
        type="checkbox"
        checked={!!goal.done}
        onChange={() => onToggle(goal._id)}
        className="goal-checkbox"
      />
      <span className={`goal-text ${goal.done ? 'completed' : ''}`}>
        {goal.text}
      </span>
    </div>
  );
}
