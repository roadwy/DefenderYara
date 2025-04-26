
rule Trojan_Win32_Injuke_DG_MTB{
	meta:
		description = "Trojan:Win32/Injuke.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 db 01 c0 31 c0 01 c0 29 c0 29 c3 01 c3 83 f3 5c 83 c3 0f 81 f3 } //2
		$a_01_1 = {83 f0 71 29 c3 83 f3 11 2d c8 00 00 00 29 c0 } //2
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}