
rule Trojan_BAT_Sabsik_DB_MTB{
	meta:
		description = "Trojan:BAT/Sabsik.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 4b 53 4b 53 44 53 44 4c 4b 53 4a 44 4c 4b 53 44 53 44 53 } //01 00  DKSKSDSDLKSJDLKSDSDS
		$a_81_1 = {52 45 74 54 53 31 4e 45 55 30 52 4d 53 31 4e 4b 52 45 78 4c 55 30 52 54 52 46 4d 6c } //01 00  REtTS1NEU0RMS1NKRExLU0RTRFMl
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}