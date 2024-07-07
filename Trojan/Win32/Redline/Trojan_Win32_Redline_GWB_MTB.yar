
rule Trojan_Win32_Redline_GWB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d 90 01 04 03 8d 90 01 04 88 01 83 3d 90 01 04 6b 75 10 90 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}