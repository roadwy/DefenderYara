
rule Trojan_Win32_Injuke_RD_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 6b 8b 4d 08 03 4d fc 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Injuke_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Injuke.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 83 e0 03 8a 04 38 30 04 0a 41 8b 46 04 8b 16 2b c2 3b c8 72 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Injuke_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Injuke.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 08 ac 34 76 aa 3c 00 75 f8 5f 5e c9 c2 04 00 } //1
		$a_01_1 = {61 00 63 00 6d 00 76 00 72 00 77 00 75 00 71 00 78 00 66 00 6e 00 37 00 2e 00 65 00 78 00 65 00 } //1 acmvrwuqxfn7.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}