
rule Trojan_Win32_Azorult_NW_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 1e 81 90 02 05 90 18 46 3b f7 90 18 81 90 02 05 90 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}