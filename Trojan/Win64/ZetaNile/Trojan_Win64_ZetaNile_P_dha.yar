
rule Trojan_Win64_ZetaNile_P_dha{
	meta:
		description = "Trojan:Win64/ZetaNile.P!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 53 50 56 30 83 7d 0c 60 66 c7 45 f8 30 35 } //1
		$a_01_1 = {53 74 61 72 74 69 6e 67 20 53 65 63 75 72 65 50 44 46 } //1 Starting SecurePDF
		$a_01_2 = {4c 6f 61 64 44 6f 63 75 6d 65 6e 74 3a 20 27 25 73 27 2c 20 74 69 64 3d 25 64 } //1 LoadDocument: '%s', tid=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}