
rule Trojan_BAT_RedLineStealer_ML_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {de 0b 08 2c 07 08 6f ?? ?? ?? 0a 00 dc 07 6f ?? ?? ?? 0a 0d de 16 07 2c 07 07 6f ?? ?? ?? 0a 00 dc } //1
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_4 = {46 69 6c 65 4c 6f 63 6b 65 64 } //1 FileLocked
		$a_01_5 = {52 65 67 69 73 74 72 79 52 65 63 6f 76 65 72 65 64 } //1 RegistryRecovered
		$a_01_6 = {53 75 73 70 65 6e 64 43 6f 75 6e 74 45 78 63 65 65 64 65 64 } //1 SuspendCountExceeded
		$a_01_7 = {50 61 73 73 77 6f 72 64 52 65 73 74 72 69 63 74 69 6f 6e } //1 PasswordRestriction
		$a_01_8 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule Trojan_BAT_RedLineStealer_ML_MTB_2{
	meta:
		description = "Trojan:BAT/RedLineStealer.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {0a fe 0e 02 00 fe 0c 02 00 20 00 01 00 00 6f ?? ?? ?? 0a fe 0c 02 00 20 80 00 00 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 20 e8 03 00 00 73 23 00 00 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 08 00 00 00 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 08 00 00 00 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe ?? ?? ?? 20 01 00 00 00 6f ?? ?? ?? 0a fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 01 00 00 00 73 2b 00 00 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 20 00 00 00 00 fe ?? ?? ?? 8e 69 6f ?? ?? ?? 0a fe ?? ?? ?? 6f ?? ?? ?? 0a dd 13 00 00 00 fe ?? ?? ?? 39 09 00 00 00 fe ?? ?? ?? 6f ?? ?? ?? 0a dc fe 0c 01 00 6f ?? ?? ?? 0a fe } //1
		$a_81_1 = {42 55 59 20 43 52 59 50 54 20 46 52 4f 4d 20 50 55 4c 53 41 52 20 43 52 59 50 54 45 52 20 2d 20 40 50 75 6c 73 61 72 43 72 79 70 74 65 72 5f 62 6f 74 } //1 BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_4 = {43 69 70 68 65 72 4d 6f 64 65 } //1 CipherMode
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_81_7 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_8 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //1 set_Password
		$a_81_9 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}