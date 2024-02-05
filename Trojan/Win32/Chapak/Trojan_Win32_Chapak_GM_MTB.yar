
rule Trojan_Win32_Chapak_GM_MTB{
	meta:
		description = "Trojan:Win32/Chapak.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 8d 87 90 02 10 33 8d 90 01 04 88 8d 90 00 } //01 00 
		$a_02_1 = {8b 4d 08 03 8d 90 01 04 8a 95 90 01 04 88 11 90 02 20 8b 45 90 01 01 03 85 90 01 04 8a 8d 90 01 04 88 08 83 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}