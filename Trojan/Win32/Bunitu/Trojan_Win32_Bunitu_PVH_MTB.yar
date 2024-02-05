
rule Trojan_Win32_Bunitu_PVH_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 55 f8 03 55 f0 8b 45 f4 03 45 f8 8b 4d fc 8a 00 88 04 11 8b 4d f8 83 c1 01 89 4d f8 eb } //01 00 
		$a_02_1 = {8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 09 25 00 a1 90 01 04 a3 90 01 04 31 0d 90 01 04 c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}