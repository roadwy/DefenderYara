
rule Trojan_Win32_RisePro_GPB_MTB{
	meta:
		description = "Trojan:Win32/RisePro.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 01 8d 48 90 01 01 30 4c 05 90 01 01 40 83 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}