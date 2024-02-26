
rule Trojan_Win32_Stealerc_GPAE_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {8a 44 24 22 30 44 0c 23 41 83 f9 } //00 00 
	condition:
		any of ($a_*)
 
}