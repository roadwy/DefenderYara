
rule Trojan_Win32_Fauppod_MO_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 c4 04 46 8a 46 ff 83 ec 04 c7 04 24 90 01 04 83 c4 04 68 90 01 04 83 c4 04 32 02 89 c0 88 07 83 c7 01 57 83 c4 04 42 68 90 01 04 83 c4 04 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}