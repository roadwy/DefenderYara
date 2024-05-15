
rule Trojan_Win64_XWorm_GPA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 6d 61 69 6e 2e 72 73 68 74 74 70 73 3a 2f 2f 31 30 37 2e 31 37 35 2e 33 2e 31 30 } //05 00  src\main.rshttps://107.175.3.10
		$a_01_1 = {2e 62 69 6e 68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 49 6e 74 65 72 6e 65 74 } //00 00  .binhttps://github.comInternet
	condition:
		any of ($a_*)
 
}