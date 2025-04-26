
rule Trojan_Win32_Badappx_A{
	meta:
		description = "Trojan:Win32/Badappx.A,SIGNATURE_TYPE_PEHSTR,ffffffdc 00 ffffffdc 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 73 75 2a 2e 74 6d 70 } //100 wsu*.tmp
		$a_01_1 = {50 6c 61 63 65 68 6f 6c 64 65 72 54 69 6c 65 4c 6f 67 6f 46 6f 6c 64 65 72 } //100 PlaceholderTileLogoFolder
		$a_01_2 = {5c 00 3f 00 3f 00 5c 00 63 00 3a 00 } //20 \??\c:
		$a_01_3 = {5c 00 3f 00 3f 00 5c 00 64 00 3a 00 } //20 \??\d:
		$a_01_4 = {5c 00 3f 00 3f 00 5c 00 65 00 3a 00 } //20 \??\e:
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20) >=220
 
}