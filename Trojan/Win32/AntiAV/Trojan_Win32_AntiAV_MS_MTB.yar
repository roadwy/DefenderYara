
rule Trojan_Win32_AntiAV_MS_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d7 c1 ea 90 01 01 03 cd 03 c7 c7 05 90 01 08 33 c8 0f 57 c0 03 d6 90 02 0c 81 3d 90 02 08 89 4c 24 90 01 01 75 90 00 } //1
		$a_02_1 = {5f 5e 5d 89 90 01 03 33 cc e8 90 01 04 81 c4 90 01 04 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}