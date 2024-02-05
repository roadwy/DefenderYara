
rule Trojan_Win32_IcedId_DBH_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6a 01 53 53 8d 45 0c 50 89 5d 0c ff d6 85 c0 75 2e 6a 08 6a 01 53 53 8d 45 0c 50 ff d6 85 c0 } //01 00 
		$a_81_1 = {77 50 42 36 47 79 30 2a 43 75 4c 69 65 6e 43 } //00 00 
	condition:
		any of ($a_*)
 
}