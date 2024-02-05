
rule Trojan_Win32_Fauppod_PH_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 01 01 90 90 90 90 90 90 ac 89 c0 32 02 89 c0 aa 42 90 90 53 83 c4 04 49 56 83 c4 04 85 c9 75 90 01 01 61 c9 c2 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}