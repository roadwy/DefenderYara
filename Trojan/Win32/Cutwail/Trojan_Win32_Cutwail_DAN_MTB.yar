
rule Trojan_Win32_Cutwail_DAN_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.DAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f b6 14 16 8b 75 dc 8b 7d d4 0f b6 34 37 31 f2 88 d3 8b 55 ec 8b 75 e8 88 1c 16 8b 45 ec 89 45 c8 8b 45 c8 05 01 00 00 00 89 45 ec eb } //00 00 
	condition:
		any of ($a_*)
 
}