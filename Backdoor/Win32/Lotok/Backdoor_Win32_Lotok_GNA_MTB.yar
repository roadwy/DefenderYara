
rule Backdoor_Win32_Lotok_GNA_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 f7 31 db b9 90 01 04 ac 49 32 06 88 07 60 fd 89 d3 50 59 fc 61 83 c6 90 01 01 83 c7 90 01 01 49 85 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}