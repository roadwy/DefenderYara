
rule Trojan_Win32_Alureon_BH{
	meta:
		description = "Trojan:Win32/Alureon.BH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 8b 43 28 6a 40 6a 15 03 c7 50 ff 15 ?? ?? ?? ?? 8b 43 28 6a 05 } //1
		$a_01_1 = {68 47 52 45 56 68 32 4c 44 54 } //1 hGREVh2LDT
		$a_01_2 = {8b 44 24 04 8a d1 02 54 24 0c 03 c1 30 10 41 3b 4c 24 08 72 eb } //1
		$a_01_3 = {80 7c 31 01 0a 74 15 8a d1 2a 55 10 32 d0 88 14 31 41 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}