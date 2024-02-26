
rule Trojan_Win32_Zenpak_AMBD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 f2 81 c2 90 01 04 81 c1 01 00 00 00 8b 90 01 04 ff 01 c6 8b 1b 8b 12 0f b7 3f 31 df 89 34 24 90 00 } //01 00 
		$a_01_1 = {8a 0c 1f 8b 55 e4 8b 5d d0 32 0c 1a 8b 55 e0 88 0c 1a 81 c3 01 00 00 00 8b 4d f0 39 cb 89 5d c8 } //00 00 
	condition:
		any of ($a_*)
 
}