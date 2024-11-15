
rule Trojan_Win32_Lazy_GV_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 4a 01 8a 02 88 4d ff 8a 4a 02 88 4d fe 8a 4a 03 83 c2 04 0f b6 c0 88 4d fd 89 55 ec 85 c0 74 34 } //1
		$a_01_1 = {3a 5c 54 65 6d 70 } //1 :\Temp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}