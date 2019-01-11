export interface Consumable {
  /**
   *
   * Mark a stored oidc-provider model as consumed (not yet expired though!). Future finds for this
   * id should be fulfilled with an object containing additional property named "consumed" with a
   * truthy value (timestamp, date, boolean, etc).
   *
   * @return {Promise} Promise fulfilled when the operation succeeded. Rejected with error when
   * encountered.
   * @param {string} id Identifier of oidc-provider model
   *
   */
  consume(id: string): Promise<void>

  isValid: boolean

  // 	  static get IN_PAYLOAD() {
  // 	return [
  // 		...super.IN_PAYLOAD,
  // 		'consumed',
  // 	];
  // }
}
