
rule Trojan_BAT_Crysan_BN_MTB{
	meta:
		description = "Trojan:BAT/Crysan.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 76 69 72 75 73 } //1 Antivirus
		$a_01_1 = {41 6e 74 69 5f 50 72 6f 63 65 73 73 } //1 Anti_Process
		$a_01_2 = {41 6e 74 69 5f 41 6e 61 6c 79 73 69 73 } //1 Anti_Analysis
		$a_01_3 = {44 65 63 6f 64 65 46 72 6f 6d 42 79 74 65 73 } //1 DecodeFromBytes
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {44 65 62 75 67 67 65 72 49 6e 61 63 74 69 76 65 } //1 DebuggerInactive
		$a_01_6 = {5f 51 72 30 70 78 44 4f 4c 30 44 35 48 38 42 47 7a 48 48 61 4d 79 57 57 62 67 6e 47 } //1 _Qr0pxDOL0D5H8BGzHHaMyWWbgnG
		$a_01_7 = {56 69 72 75 73 49 6e 66 65 63 74 65 64 } //1 VirusInfected
		$a_01_8 = {56 69 72 75 73 44 65 6c 65 74 65 64 } //1 VirusDeleted
		$a_01_9 = {44 65 63 6f 64 65 46 72 6f 6d 46 69 6c 65 } //1 DecodeFromFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}