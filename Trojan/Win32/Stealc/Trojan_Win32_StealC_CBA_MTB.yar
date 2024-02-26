
rule Trojan_Win32_StealC_CBA_MTB{
	meta:
		description = "Trojan:Win32/StealC.CBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 30 04 0e 83 7c 24 18 0f 75 25 } //00 00 
	condition:
		any of ($a_*)
 
}