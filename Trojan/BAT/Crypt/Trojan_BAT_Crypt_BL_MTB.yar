
rule Trojan_BAT_Crypt_BL_MTB{
	meta:
		description = "Trojan:BAT/Crypt.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 76 73 64 76 64 73 73 64 2e 65 78 65 } //01 00  bvsdvdssd.exe
		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_2 = {52 65 61 64 42 79 74 65 } //01 00  ReadByte
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}