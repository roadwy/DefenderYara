
rule Trojan_BAT_RedLineStealer_NJ_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 61 00 73 00 64 00 61 00 73 00 64 00 61 00 73 00 64 00 64 00 61 00 73 00 73 00 6a 00 64 00 73 00 75 00 64 00 61 00 62 00 73 00 68 00 61 00 64 00 61 00 64 00 } //01 00  aasdasdasddassjdsudabshadad
		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_4 = {4f 61 68 61 59 6f } //01 00  OahaYo
		$a_01_5 = {61 34 66 30 33 35 65 39 30 34 30 33 } //01 00  a4f035e90403
		$a_01_6 = {9f b6 2b 09 0e 00 00 00 9a 00 23 00 06 00 00 01 00 00 00 7d 00 00 00 bc } //00 00 
	condition:
		any of ($a_*)
 
}