
rule Trojan_Win32_Stealc_GKI_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 03 4d fc 8b 55 08 03 55 f8 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 8b 45 fc 33 d2 f7 35 90 01 04 85 d2 75 90 01 01 8b 55 f8 03 15 90 01 04 89 55 f8 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}