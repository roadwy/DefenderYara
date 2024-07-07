
rule Trojan_BAT_SnakeKeylogger_RPS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 "
		
	strings :
		$a_01_0 = {47 75 6c 6e 61 72 } //1 Gulnar
		$a_01_1 = {4d 69 72 61 72 6d 61 72 } //1 Mirarmar
		$a_01_2 = {48 61 73 65 6e 64 61 } //1 Hasenda
		$a_01_3 = {50 61 72 61 64 69 73 65 } //1 Paradise
		$a_01_4 = {42 6f 6f 74 43 61 6d 70 } //1 BootCamp
		$a_01_5 = {53 74 6f 72 65 } //1 Store
		$a_01_6 = {48 65 6c 70 65 72 5f 43 6c 61 73 73 65 73 } //1 Helper_Classes
		$a_01_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_9 = {56 70 6e 43 6c 69 65 6e 74 57 72 61 70 70 65 72 } //1 VpnClientWrapper
		$a_01_10 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_11 = {56 70 6e 43 6f 6e 6e 65 63 74 53 65 72 76 69 63 65 } //1 VpnConnectService
		$a_01_12 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_13 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_14 = {42 69 67 45 6e 64 69 61 6e 55 6e 69 63 6f 64 65 } //1 BigEndianUnicode
		$a_01_15 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_16 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_17 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_18 = {4c 65 6e 67 74 68 } //1 Length
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=19
 
}