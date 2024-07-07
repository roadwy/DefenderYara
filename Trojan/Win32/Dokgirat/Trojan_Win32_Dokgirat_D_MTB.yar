
rule Trojan_Win32_Dokgirat_D_MTB{
	meta:
		description = "Trojan:Win32/Dokgirat.D!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 66 69 6e 61 6c 31 73 74 73 70 79 5c 6c 6f 61 64 64 6c 6c 5c 72 65 6c 65 61 73 65 5c 6c 6f 61 64 64 6c 6c 2e 70 64 62 } //1 \final1stspy\loaddll\release\loaddll.pdb
		$a_01_1 = {8a 14 39 80 c2 7a 80 f2 19 88 14 39 41 3b ce 7c ef } //1
		$a_01_2 = {80 34 38 50 40 3b c6 7c f7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}