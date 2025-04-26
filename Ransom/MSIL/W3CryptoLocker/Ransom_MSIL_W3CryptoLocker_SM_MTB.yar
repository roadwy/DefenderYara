
rule Ransom_MSIL_W3CryptoLocker_SM_MTB{
	meta:
		description = "Ransom:MSIL/W3CryptoLocker.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_02_0 = {91 07 61 06 09 91 61 d2 9c 90 0a f0 00 00 28 ?? ?? ?? ?? 03 6f ?? ?? ?? ?? 0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 8d ?? ?? ?? ?? 0c 16 0d 16 13 04 38 ?? ?? ?? ?? 00 08 11 04 02 11 04 } //4
	condition:
		((#a_02_0  & 1)*4) >=4
 
}