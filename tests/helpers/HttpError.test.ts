import HttpError from '../../src/helpers/HttpError';

describe('HttpError', () => {
  it('stores statusCode and sanitized message', () => {
    const err = new HttpError(400, 'Bad');
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe('Bad');
  });
});
