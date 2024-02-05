
rule Trojan_Win32_Ursnif_GB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 37 4e c7 44 24 90 02 30 81 e3 90 01 04 81 6c 24 90 02 30 81 44 24 90 02 30 81 6c 24 90 02 30 c1 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}