
rule Trojan_Win32_BlackMoon_Z_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 03 83 c3 90 01 01 8b 73 90 01 01 89 04 90 01 01 89 fa 89 f8 0f b6 e8 c1 ea 90 01 01 89 f0 8b 94 90 00 } //02 00 
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //00 00  BlackMoon RunTime Error:
	condition:
		any of ($a_*)
 
}