
rule Ransom_MSIL_CryptoJoker_PAA_MTB{
	meta:
		description = "Ransom:MSIL/CryptoJoker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 79 20 6e 61 6d 65 20 69 73 20 43 72 79 70 74 6f 4a 6f 6b 65 72 20 21 21 } //01 00  my name is CryptoJoker !!
		$a_01_1 = {67 65 74 5f 43 72 79 70 74 6f 4a 6f 6b 65 72 4d 65 73 73 61 67 65 } //01 00  get_CryptoJokerMessage
		$a_01_2 = {49 20 61 6d 20 72 61 6e 73 6f 6d 77 61 72 65 } //01 00  I am ransomware
		$a_01_3 = {6a 6f 6b 2e 63 72 79 70 74 } //01 00  jok.crypt
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  SELECT * FROM Win32_OperatingSystem
		$a_01_5 = {77 00 69 00 6e 00 33 00 32 00 5f 00 6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 64 00 69 00 73 00 6b 00 2e 00 64 00 65 00 76 00 69 00 63 00 65 00 69 00 64 00 3d 00 22 00 } //01 00  win32_logicaldisk.deviceid="
		$a_01_6 = {5c 00 65 00 6e 00 63 00 4b 00 65 00 79 00 2e 00 63 00 72 00 79 00 70 00 74 00 } //00 00  \encKey.crypt
	condition:
		any of ($a_*)
 
}