
rule Trojan_Win32_Zenpak_CX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 50 6a 00 ff 15 } //2
		$a_03_1 = {f3 a5 8b ca 83 e1 ?? f3 a4 } //2
		$a_03_2 = {51 53 33 ff 57 6a 01 57 52 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? ff d3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}