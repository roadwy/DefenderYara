
rule Trojan_Win32_Sefnit_BJ{
	meta:
		description = "Trojan:Win32/Sefnit.BJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8b d7 bb ?? ?? ?? ?? 66 33 1c 01 66 89 18 83 c0 02 4a 75 ee } //3
		$a_03_1 = {39 7e 4c 72 05 8b 7e 38 eb 03 8d 7e 38 ff 75 ?? 8b cb 68 } //3
		$a_01_2 = {2d 00 67 00 70 00 75 00 3d 00 00 00 } //1
		$a_01_3 = {63 00 75 00 64 00 61 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 70 00 75 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}