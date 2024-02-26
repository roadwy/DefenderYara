
rule Trojan_Win32_Ekstak_ASEI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {50 51 56 ff 15 90 01 03 00 8b e8 8a 44 24 60 89 6c 24 1c 84 c0 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}