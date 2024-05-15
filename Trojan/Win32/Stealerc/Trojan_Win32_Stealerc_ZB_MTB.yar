
rule Trojan_Win32_Stealerc_ZB_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 14 1e 83 ff 0f } //01 00 
		$a_01_1 = {46 3b f7 7c } //00 00 
	condition:
		any of ($a_*)
 
}