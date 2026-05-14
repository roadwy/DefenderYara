
rule Backdoor_BAT_Caminho_ARP_AMTB{
	meta:
		description = "Backdoor:BAT/Caminho.ARP!AMTB,SIGNATURE_TYPE_PEHSTR,16 00 16 00 0b 00 00 "
		
	strings :
		$a_01_0 = {63 61 6d 69 6e 68 6f } //15 caminho
		$a_01_1 = {70 61 79 6c 6f 61 64 42 75 66 66 65 72 } //1 payloadBuffer
		$a_01_2 = {75 61 63 50 61 79 6c 6f 61 64 55 72 6c } //1 uacPayloadUrl
		$a_01_3 = {65 6e 63 6f 64 65 64 50 61 79 6c 6f 61 64 55 72 6c } //1 encodedPayloadUrl
		$a_01_4 = {65 6e 63 6f 64 65 64 55 72 6c 50 61 79 6c 6f 61 64 } //1 encodedUrlPayload
		$a_01_5 = {44 73 43 72 61 63 6b 4e 61 6d 65 73 } //1 DsCrackNames
		$a_01_6 = {41 6c 6c 6f 77 69 6e 67 53 74 61 72 74 4f 6e 52 65 6d 6f 74 65 41 70 70 53 65 73 73 69 6f 6e } //1 AllowingStartOnRemoteAppSession
		$a_01_7 = {73 65 74 5f 4c 6f 67 6f 6e 54 79 70 65 } //1 set_LogonType
		$a_01_8 = {73 65 74 5f 55 73 65 72 50 61 73 73 77 6f 72 64 } //1 set_UserPassword
		$a_01_9 = {73 65 74 5f 55 73 65 72 41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e } //1 set_UserAccountDomain
		$a_01_10 = {4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 33 32 2e 54 61 73 6b 53 63 68 65 64 75 6c 65 72 2e 54 72 69 67 67 65 72 3e 2e 41 64 64 } //1 Microsoft.Win32.TaskScheduler.Trigger>.Add
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=22
 
}