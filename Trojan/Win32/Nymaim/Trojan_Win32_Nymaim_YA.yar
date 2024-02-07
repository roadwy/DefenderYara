
rule Trojan_Win32_Nymaim_YA{
	meta:
		description = "Trojan:Win32/Nymaim.YA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 62 68 69 6e 6c 6c 79 74 6e 68 67 6c 6d 76 73 69 } //01 00  ybhinllytnhglmvsi
		$a_01_1 = {6a 66 6c 6c 7a 75 6e 64 70 78 6d 78 70 73 7a 6c } //01 00  jfllzundpxmxpszl
		$a_01_2 = {70 62 6b 69 6c 66 6b 79 75 } //00 00  pbkilfkyu
		$a_00_3 = {5d 04 00 } //00 71 
	condition:
		any of ($a_*)
 
}