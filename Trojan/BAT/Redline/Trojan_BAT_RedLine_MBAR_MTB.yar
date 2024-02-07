
rule Trojan_BAT_RedLine_MBAR_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 6c 6b 46 53 6f 64 64 62 65 2e 65 78 65 00 6a 6c 6b 46 53 6f 64 64 62 65 00 3c } //02 00 
		$a_01_1 = {66 64 66 66 66 6a 66 66 73 66 66 61 67 66 63 66 64 73 73 66 6b 66 68 67 6a } //02 00  fdfffjffsffagfcfdssfkfhgj
		$a_01_2 = {68 64 73 73 64 67 66 64 66 6b 73 68 66 66 66 64 6a } //02 00  hdssdgfdfkshfffdj
		$a_01_3 = {73 66 68 6a 66 6b 66 68 66 6a 73 66 68 64 68 66 66 66 66 66 61 66 64 73 66 67 66 73 73 73 63 66 67 64 62 } //01 00  sfhjfkfhfjsfhdhfffffafdsfgfssscfgdb
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}