
rule Trojan_BAT_RedLine_NZD_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {6a 66 73 64 73 73 73 73 73 73 90 02 02 68 64 68 66 64 66 6b 67 90 00 } //03 00 
		$a_01_1 = {6a 64 64 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 66 } //03 00  jddssssssssssssssssssssssf
		$a_01_2 = {66 66 66 66 66 64 68 66 6b 66 66 64 67 6a } //03 00  fffffdhfkffdgj
		$a_01_3 = {6a 68 66 66 73 64 } //01 00  jhffsd
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}