
rule Trojan_Win32_Sefnit_AW{
	meta:
		description = "Trojan:Win32/Sefnit.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 89 0c 07 83 c7 02 83 ff ?? 72 dc 8b c6 e8 ?? ?? ?? ?? c3 90 09 0e 00 8b c6 b9 ?? ?? ?? ?? 66 33 8f } //1
		$a_03_1 = {83 c2 05 c1 e2 0a 52 90 09 0c 00 6a 64 59 99 f7 f9 8d 8d } //1
		$a_01_2 = {6a 07 59 33 f6 33 d2 89 48 14 89 70 10 66 89 10 89 75 fc 89 48 30 89 70 2c 66 89 50 1c c6 45 fc 01 89 48 4c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}