
rule Trojan_Win32_ICLoader_VDSK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 55 0c 03 c1 8a 0d 90 01 04 03 c2 8a 10 32 d1 8b 4d 08 88 10 83 3d 90 01 04 03 76 90 00 } //02 00 
		$a_02_1 = {8a 0c 11 88 0c 06 8a 8a 90 01 04 84 c9 75 90 01 01 8b 0d 90 01 04 03 ca 03 c1 8a 0d 90 01 04 30 08 83 3d 90 01 04 03 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}