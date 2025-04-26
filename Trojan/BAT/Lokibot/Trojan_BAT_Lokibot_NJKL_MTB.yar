
rule Trojan_BAT_Lokibot_NJKL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.NJKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 16 00 00 "
		
	strings :
		$a_81_0 = {4d 49 43 52 4f 53 4f 46 54 45 44 50 50 45 52 4d 49 53 53 49 56 45 41 50 50 49 4e 46 4f } //1 MICROSOFTEDPPERMISSIVEAPPINFO
		$a_81_1 = {47 4f 4f 47 4c 45 55 50 44 41 54 45 41 50 50 4c 49 43 41 54 49 4f 4e 43 4f 4d 4d 41 4e 44 53 } //1 GOOGLEUPDATEAPPLICATIONCOMMANDS
		$a_81_2 = {31 39 38 20 50 72 6f 74 65 63 74 6f 72 20 56 32 } //1 198 Protector V2
		$a_81_3 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //1 Select * from Win32_ComputerSystem
		$a_81_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_5 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_81_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_8 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_9 = {63 69 70 68 65 72 54 65 78 74 } //1 cipherText
		$a_81_10 = {49 41 73 79 6e 63 52 65 73 75 6c 74 } //1 IAsyncResult
		$a_81_11 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_81_12 = {4c 6f 61 64 65 72 46 6c 61 67 73 } //1 LoaderFlags
		$a_81_13 = {64 6f 74 4e 65 74 50 72 6f 74 65 63 74 6f 72 } //1 dotNetProtector
		$a_81_14 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_15 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_81_16 = {41 73 73 65 6d 62 6c 79 42 75 69 6c 64 65 72 } //1 AssemblyBuilder
		$a_81_17 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_81_18 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_19 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_20 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //1 ObfuscatedByGoliath
		$a_81_21 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1+(#a_81_19  & 1)*1+(#a_81_20  & 1)*1+(#a_81_21  & 1)*1) >=22
 
}