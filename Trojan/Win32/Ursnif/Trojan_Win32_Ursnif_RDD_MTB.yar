
rule Trojan_Win32_Ursnif_RDD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 43 01 99 8b f8 8b da 8b 54 24 24 03 fd } //00 00 
	condition:
		any of ($a_*)
 
}