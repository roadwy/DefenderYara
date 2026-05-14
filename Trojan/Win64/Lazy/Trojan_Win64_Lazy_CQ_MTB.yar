
rule Trojan_Win64_Lazy_CQ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 c7 c0 60 00 00 00 65 48 8b 38 48 8b 7f 18 48 8b 7f 20 48 8b 7f 20 48 8b 83 13 01 00 00 48 01 f8 ff d0 48 89 83 13 01 00 00 48 8b 83 1b 01 00 00 48 01 f8 ff d0 } //1
		$a_81_1 = {50 79 49 6d 70 6f 72 74 5f 49 6d 70 6f 72 74 4d 6f 64 75 6c 65 } //1 PyImport_ImportModule
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}