
rule Trojan_Win32_Glupteba_PU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 33 81 90 02 05 90 18 46 3b f7 90 18 81 90 02 05 90 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}