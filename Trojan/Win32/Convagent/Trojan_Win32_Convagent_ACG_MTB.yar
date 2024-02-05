
rule Trojan_Win32_Convagent_ACG_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 50 57 ff d3 85 c0 75 90 01 01 83 fe 28 0f 8e 90 01 04 8d 44 24 1c 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}