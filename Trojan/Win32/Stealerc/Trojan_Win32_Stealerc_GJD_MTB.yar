
rule Trojan_Win32_Stealerc_GJD_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 03 85 90 01 04 0f b6 08 8b 95 90 01 04 0f b6 84 15 90 01 04 8b 95 90 01 04 0f b6 94 15 90 01 04 03 c2 25 ff 00 00 80 79 90 01 01 48 0d 90 01 04 40 0f b6 84 05 90 01 04 33 c8 8b 55 f8 03 95 90 01 04 88 0a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}