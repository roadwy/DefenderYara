
rule Trojan_BAT_AgentTesla_X_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {06 13 07 19 8d 90 01 03 01 80 90 01 03 04 7e 90 01 03 04 16 7e 90 01 03 04 a2 7e 90 01 03 04 17 7e 90 01 03 04 a2 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_X_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.X!MTB,SIGNATURE_TYPE_PEHSTR,28 00 28 00 10 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 } //0a 00  System.Drawing.Bitmap
		$a_01_1 = {44 45 53 5f 44 65 63 72 79 70 74 } //0a 00  DES_Decrypt
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {43 6f 6e 66 75 73 65 72 45 78 } //01 00  ConfuserEx
		$a_01_6 = {5f 74 69 63 6b 65 72 5f 54 69 63 6b } //01 00  _ticker_Tick
		$a_01_7 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_8 = {45 76 65 6e 74 41 72 67 73 } //01 00  EventArgs
		$a_01_9 = {73 65 6e 64 65 72 } //01 00  sender
		$a_01_10 = {66 6c 61 74 42 75 74 74 6f 6e 33 5f 43 6c 69 63 6b } //01 00  flatButton3_Click
		$a_01_11 = {70 61 73 73 77 6f 72 64 } //01 00  password
		$a_01_12 = {57 65 62 42 72 6f 77 73 65 72 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 64 45 76 65 6e 74 41 72 67 73 } //01 00  WebBrowserDocumentCompletedEventArgs
		$a_01_13 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00  BlockCopy
		$a_01_14 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_01_15 = {43 61 70 74 75 72 65 } //00 00  Capture
	condition:
		any of ($a_*)
 
}