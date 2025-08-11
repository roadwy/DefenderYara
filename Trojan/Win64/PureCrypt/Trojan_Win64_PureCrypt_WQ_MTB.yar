
rule Trojan_Win64_PureCrypt_WQ_MTB{
	meta:
		description = "Trojan:Win64/PureCrypt.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 40 48 00 15 13 80 33 c9 48 89 48 08 c7 40 48 01 15 13 80 c7 40 48 0e 00 07 80 48 8b 0d 99 9f 15 00 48 8d 49 08 48 8b d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}