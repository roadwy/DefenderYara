
rule Trojan_Win32_Cobaltstrike_APS_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.APS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 39 18 75 51 bb 90 01 04 66 39 58 02 75 46 bb 90 01 04 66 39 58 04 75 3b bb 90 01 04 66 39 58 06 75 30 bb 90 01 04 66 39 58 08 75 25 bb 90 01 04 66 39 58 0a 75 1a bb 73 73 00 00 66 39 58 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}