
rule Trojan_BAT_RedLineStealer_MAF_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {42 55 59 20 43 52 59 50 } //1 BUY CRYP
		$a_81_1 = {40 50 75 6c 73 61 72 43 72 79 70 74 65 72 5f 62 6f 74 } //1 @PulsarCrypter_bot
		$a_81_2 = {53 72 75 48 43 6a 61 } //1 SruHCja
		$a_81_3 = {54 4a 77 4b 4e 77 56 68 45 } //1 TJwKNwVhE
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_7 = {57 6f 77 36 34 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 Wow64GetThreadContext
		$a_81_8 = {47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 GetThreadContext
		$a_81_9 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_81_10 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_11 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_81_12 = {44 79 6e 61 6d 69 63 44 6c 6c 49 6e 76 6f 6b 65 } //1 DynamicDllInvoke
		$a_81_13 = {44 79 6e 61 6d 69 63 44 6c 6c 4d 6f 64 75 6c 65 } //1 DynamicDllModule
		$a_81_14 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}