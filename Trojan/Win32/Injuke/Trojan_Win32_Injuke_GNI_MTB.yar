
rule Trojan_Win32_Injuke_GNI_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 38 38 7c 00 d5 96 78 00 00 da 0a 00 73 } //00 00 
	condition:
		any of ($a_*)
 
}