
rule Trojan_Win32_Emotet_CB{
	meta:
		description = "Trojan:Win32/Emotet.CB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {5d c2 0c 00 31 35 90 01 02 45 00 31 05 90 01 02 45 00 e8 90 01 02 ff ff 89 45 fc 55 89 e5 90 00 } //01 00 
		$a_00_1 = {43 72 79 70 74 44 75 70 6c 69 63 61 74 65 4b 65 79 } //01 00  CryptDuplicateKey
		$a_00_2 = {46 6c 75 73 68 50 72 6f 63 65 73 73 57 72 69 74 65 42 75 66 66 65 72 73 } //01 00  FlushProcessWriteBuffers
		$a_00_3 = {65 00 73 00 65 00 6e 00 74 00 75 00 74 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  esentutl.exe
		$a_00_4 = {44 00 65 00 6d 00 6f 00 53 00 68 00 69 00 65 00 6c 00 64 00 } //00 00  DemoShield
	condition:
		any of ($a_*)
 
}