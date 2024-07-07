
rule Trojan_Win64_CryptInject_FS_dha{
	meta:
		description = "Trojan:Win64/CryptInject.FS!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 40 58 48 89 44 24 60 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}