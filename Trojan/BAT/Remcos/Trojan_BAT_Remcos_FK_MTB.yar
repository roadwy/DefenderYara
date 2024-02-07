
rule Trojan_BAT_Remcos_FK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_1 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 73 } //01 00  Start-Sleep -s
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_81_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_6 = {2f 73 74 6f 72 65 32 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f } //00 00  /store2.gofile.io/download/
	condition:
		any of ($a_*)
 
}