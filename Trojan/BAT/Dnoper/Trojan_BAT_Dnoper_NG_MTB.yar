
rule Trojan_BAT_Dnoper_NG_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {91 03 61 1f 1a 5f 9c 59 } //01 00 
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_81_2 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_4 = {41 6e 74 69 76 69 72 75 73 } //00 00  Antivirus
	condition:
		any of ($a_*)
 
}