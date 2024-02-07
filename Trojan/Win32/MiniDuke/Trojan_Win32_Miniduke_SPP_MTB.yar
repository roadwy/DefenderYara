
rule Trojan_Win32_Miniduke_SPP_MTB{
	meta:
		description = "Trojan:Win32/Miniduke.SPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 d0 73 1f 8b 45 f0 03 45 f8 0f b6 08 0f b6 55 e7 03 55 f8 0f b6 c2 33 c8 8b 55 e0 03 55 f8 88 0a eb d0 } //02 00 
		$a_01_1 = {61 64 6f 62 65 61 72 6d 2e 74 6d 70 } //02 00  adobearm.tmp
		$a_01_2 = {41 00 64 00 6f 00 62 00 65 00 54 00 72 00 61 00 79 00 2e 00 64 00 6c 00 6c 00 } //00 00  AdobeTray.dll
	condition:
		any of ($a_*)
 
}