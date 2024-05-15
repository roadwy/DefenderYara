
rule Trojan_Win32_Vidar_ASDN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 04 02 32 04 19 88 03 ff } //0a 00 
		$a_01_1 = {8a 04 02 32 04 39 88 07 ff } //00 00 
	condition:
		any of ($a_*)
 
}