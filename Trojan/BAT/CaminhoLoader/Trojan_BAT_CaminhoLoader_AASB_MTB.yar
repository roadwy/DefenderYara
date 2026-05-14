
rule Trojan_BAT_CaminhoLoader_AASB_MTB{
	meta:
		description = "Trojan:BAT/CaminhoLoader.AASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0d 00 00 "
		
	strings :
		$a_80_0 = {63 61 6d 69 6e 68 6f } //caminho  5
		$a_80_1 = {70 61 79 6c 6f 61 64 42 75 66 66 65 72 } //payloadBuffer  1
		$a_80_2 = {76 6d 44 65 74 65 63 74 69 6f 6e 4e 61 6d 65 } //vmDetectionName  1
		$a_80_3 = {75 61 63 50 61 79 6c 6f 61 64 55 72 6c } //uacPayloadUrl  1
		$a_80_4 = {65 6e 63 6f 64 65 64 55 72 6c 50 61 79 6c 6f 61 64 } //encodedUrlPayload  1
		$a_80_5 = {44 73 43 72 61 63 6b 4e 61 6d 65 73 } //DsCrackNames  1
		$a_80_6 = {41 6c 6c 6f 77 69 6e 67 53 74 61 72 74 4f 6e 52 65 6d 6f 74 65 41 70 70 53 65 73 73 69 6f 6e } //AllowingStartOnRemoteAppSession  1
		$a_80_7 = {73 65 74 5f 4c 6f 67 6f 6e 54 79 70 65 } //set_LogonType  1
		$a_80_8 = {73 65 74 5f 55 73 65 72 50 61 73 73 77 6f 72 64 } //set_UserPassword  1
		$a_80_9 = {73 65 74 5f 55 73 65 72 41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e } //set_UserAccountDomain  1
		$a_80_10 = {4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 33 32 2e 54 61 73 6b 53 63 68 65 64 75 6c 65 72 2e 54 72 69 67 67 65 72 3e 2e 41 64 64 } //Microsoft.Win32.TaskScheduler.Trigger>.Add  1
		$a_80_11 = {69 73 20 74 61 6d 70 65 72 65 64 2e } //is tampered.  1
		$a_80_12 = {44 65 62 75 67 67 65 72 20 44 65 74 65 63 74 65 64 } //Debugger Detected  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=17
 
}