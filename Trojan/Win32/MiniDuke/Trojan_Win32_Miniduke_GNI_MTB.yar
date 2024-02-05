
rule Trojan_Win32_Miniduke_GNI_MTB{
	meta:
		description = "Trojan:Win32/Miniduke.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {83 7d d8 10 8b 7d c4 73 03 8d 7d c4 8b 55 e8 8b c8 83 e1 03 03 c9 03 c9 03 c9 d3 ea 8b 4d d4 d1 e9 03 cf 32 14 01 40 88 54 30 ff 3d 00 00 20 00 } //01 00 
		$a_80_1 = {43 6c 69 65 6e 74 55 49 2e 65 78 65 } //ClientUI.exe  00 00 
	condition:
		any of ($a_*)
 
}