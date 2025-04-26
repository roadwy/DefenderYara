
rule Trojan_Win32_Redline_GWY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 45 f4 01 d0 0f b6 08 8b 45 f4 83 e0 03 89 c2 8b 45 10 01 d0 0f b6 10 8b 5d 08 8b 45 f4 01 d8 31 ca 88 10 83 45 f4 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}