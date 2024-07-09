
rule Trojan_BAT_AgentTesla_X_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 13 07 19 8d ?? ?? ?? 01 80 ?? ?? ?? 04 7e ?? ?? ?? 04 16 7e ?? ?? ?? 04 a2 7e ?? ?? ?? 04 17 7e ?? ?? ?? 04 a2 38 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_X_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.X!MTB,SIGNATURE_TYPE_PEHSTR,28 00 28 00 10 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 } //10 System.Drawing.Bitmap
		$a_01_1 = {44 45 53 5f 44 65 63 72 79 70 74 } //10 DES_Decrypt
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //10 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_5 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
		$a_01_6 = {5f 74 69 63 6b 65 72 5f 54 69 63 6b } //1 _ticker_Tick
		$a_01_7 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_8 = {45 76 65 6e 74 41 72 67 73 } //1 EventArgs
		$a_01_9 = {73 65 6e 64 65 72 } //1 sender
		$a_01_10 = {66 6c 61 74 42 75 74 74 6f 6e 33 5f 43 6c 69 63 6b } //1 flatButton3_Click
		$a_01_11 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_01_12 = {57 65 62 42 72 6f 77 73 65 72 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 64 45 76 65 6e 74 41 72 67 73 } //1 WebBrowserDocumentCompletedEventArgs
		$a_01_13 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_01_14 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
		$a_01_15 = {43 61 70 74 75 72 65 } //1 Capture
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=40
 
}