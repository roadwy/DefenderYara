
rule Trojan_Win32_Redline_GWC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ec 33 c9 39 4d 0c 76 17 8b 55 08 8b c1 83 e0 03 8a 80 90 01 04 30 04 11 41 3b 4d 0c 72 ec 5d 90 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}