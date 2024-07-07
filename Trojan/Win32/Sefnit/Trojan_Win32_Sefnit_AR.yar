
rule Trojan_Win32_Sefnit_AR{
	meta:
		description = "Trojan:Win32/Sefnit.AR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 f8 02 75 7f 8b 46 04 66 83 38 2f 75 38 0f b7 48 02 66 83 f9 49 74 06 66 83 f9 55 75 28 } //1
		$a_03_1 = {8a 14 01 80 f2 90 01 01 88 10 40 83 ed 01 75 f2 8b 43 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}