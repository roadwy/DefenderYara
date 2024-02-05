
rule Ransom_MSIL_W3CryptoLocker_SN_MTB{
	meta:
		description = "Ransom:MSIL/W3CryptoLocker.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_02_0 = {0c 2b 00 08 2a 90 0a f0 00 72 90 01 04 28 90 01 04 28 90 01 04 72 90 01 04 28 90 01 04 20 90 01 04 14 14 17 8d 90 01 04 25 16 28 90 01 04 72 90 01 04 72 90 01 04 6f 90 01 04 28 90 01 04 28 90 01 04 a2 6f 90 01 04 74 90 01 04 0a 06 6f 90 01 04 16 9a 6f 90 01 04 19 9a 14 03 6f 90 01 04 0b 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}