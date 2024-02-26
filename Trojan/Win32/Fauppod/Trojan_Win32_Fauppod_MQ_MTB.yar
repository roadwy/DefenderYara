
rule Trojan_Win32_Fauppod_MQ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 06 83 c6 01 83 ec 04 c7 04 24 90 01 04 83 c4 04 68 90 01 04 83 c4 04 32 02 88 07 47 83 ec 04 90 00 } //05 00 
		$a_03_1 = {83 c4 04 83 c2 01 68 90 01 04 83 c4 04 68 90 01 04 83 c4 04 49 90 02 04 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}