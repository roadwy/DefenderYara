
rule Trojan_Win32_Upatre_MC_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 57 ff 15 } //1
		$a_01_1 = {56 8d 44 24 2c 50 ff 74 24 1c 53 ff 74 24 20 ff 15 } //1
		$a_01_2 = {8b 4c 24 1c 8d 44 41 04 50 53 ff 74 24 28 ff 15 } //1
		$a_01_3 = {68 00 65 00 6e 00 69 00 73 00 2e 00 65 00 78 00 65 00 } //1 henis.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}