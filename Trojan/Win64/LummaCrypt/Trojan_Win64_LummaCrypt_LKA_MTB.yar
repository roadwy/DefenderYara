
rule Trojan_Win64_LummaCrypt_LKA_MTB{
	meta:
		description = "Trojan:Win64/LummaCrypt.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 ca 48 c1 ea 90 01 01 48 c1 f9 90 01 01 01 d1 69 c9 90 01 02 00 00 29 c8 89 04 bb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}