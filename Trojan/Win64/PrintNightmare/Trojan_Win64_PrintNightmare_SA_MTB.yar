
rule Trojan_Win64_PrintNightmare_SA_MTB{
	meta:
		description = "Trojan:Win64/PrintNightmare.SA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 } //1 Administrators
		$a_01_1 = {5c 6e 69 67 68 74 6d 61 72 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6e 69 67 68 74 6d 61 72 65 2e 70 64 62 } //1 \nightmare\x64\Release\nightmare.pdb
		$a_01_2 = {6e 69 67 68 74 6d 61 72 65 2e 64 6c 6c } //1 nightmare.dll
		$a_01_3 = {42 00 61 00 74 00 6d 00 61 00 6e 00 34 00 32 00 21 00 } //1 Batman42!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}