
rule Trojan_BAT_RemcosRAT_AC_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 70 74 63 73 2e 65 78 65 } //1 Zptcs.exe
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 34 00 30 00 2f 00 42 00 72 00 71 00 64 00 72 00 75 00 72 00 2e 00 6d 00 70 00 34 00 } //1 http://80.66.75.40/Brqdrur.mp4
		$a_01_2 = {d0 0e 00 00 01 28 16 00 00 06 11 02 74 08 00 00 01 6f 09 00 00 0a 28 03 00 00 2b 72 3f 00 00 70 28 17 00 00 06 28 04 00 00 2b 6f 0c 00 00 0a 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}