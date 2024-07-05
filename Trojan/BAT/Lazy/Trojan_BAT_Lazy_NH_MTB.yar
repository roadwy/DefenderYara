
rule Trojan_BAT_Lazy_NH_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_81_0 = {5f 63 72 79 70 74 65 64 2e 65 78 65 } //05 00  _crypted.exe
		$a_81_1 = {66 69 6c 65 5f } //01 00  file_
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //00 00  GetTempFileName
	condition:
		any of ($a_*)
 
}