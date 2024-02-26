
rule Backdoor_Win32_Lotok_ALK_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac 49 32 06 88 07 83 c6 01 53 bb 90 01 04 4b 5b 83 c7 01 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}