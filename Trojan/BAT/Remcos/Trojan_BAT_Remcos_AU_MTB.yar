
rule Trojan_BAT_Remcos_AU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 00 37 00 32 00 2e 00 32 00 34 00 35 00 2e 00 31 00 34 00 32 00 2e 00 33 00 35 00 } //01 00  172.245.142.35
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_6 = {4e 00 61 00 6d 00 65 00 73 00 2f 00 4e 00 61 00 6d 00 65 00 } //00 00  Names/Name
	condition:
		any of ($a_*)
 
}