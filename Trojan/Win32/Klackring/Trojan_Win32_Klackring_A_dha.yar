
rule Trojan_Win32_Klackring_A_dha{
	meta:
		description = "Trojan:Win32/Klackring.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {b6 b7 2d 8c c7 ?? ?? 6b 5f 14 df c7 ?? ?? b1 38 a1 73 c7 ?? ?? 89 c1 d2 c4 } //1
		$a_03_1 = {b6 b7 2d 8c c7 84 24 ?? ?? ?? ?? 6b 5f 14 df c7 84 24 ?? ?? ?? ?? b1 38 a1 73 c7 84 24 ?? ?? ?? ?? 89 c1 d2 c4 } //1
		$a_03_2 = {71 15 05 7c c7 ?? ?? 53 21 28 09 c7 ?? ?? 2c 10 35 99 c7 ?? ?? 7c 4f 58 8e } //1
		$a_03_3 = {71 15 05 7c c7 84 24 ?? ?? ?? ?? 53 21 28 09 c7 84 24 ?? ?? ?? ?? 2c 10 35 99 c7 84 24 ?? ?? ?? ?? 7c 4f 58 8e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}