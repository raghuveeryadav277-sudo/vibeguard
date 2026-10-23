// VULN: xss
// Fixture: React dangerouslySetInnerHTML with user input

import React from 'react';

export function UserBio({ userHtml }) {
  return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;
}

export function CommentBody({ commentHtml }) {
  return <div dangerouslySetInnerHTML={{ __html: commentHtml }} />;
}
