
rule Trojan_Win64_CryptInject_TT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.TT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 48 8b 04 25 30 00 00 00 bb 01 00 00 00 48 8b 48 60 48 8b 69 10 } //1
		$a_01_1 = {48 75 61 6e 4c 6f 61 64 65 72 2e 70 64 62 } //1 HuanLoader.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}