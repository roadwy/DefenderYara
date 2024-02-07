
rule Backdoor_BAT_Crysen_AD_MTB{
	meta:
		description = "Backdoor:BAT/Crysen.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 35 30 39 43 65 72 74 69 66 69 63 61 74 65 } //01 00  X509Certificate
		$a_01_1 = {56 61 6c 69 64 61 74 65 53 65 72 76 65 72 43 65 72 74 69 66 69 63 61 74 65 } //01 00  ValidateServerCertificate
		$a_01_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  set_UseShellExecute
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_5 = {52 65 6d 6f 74 65 43 65 72 74 69 66 69 63 61 74 65 56 61 6c 69 64 61 74 69 6f 6e 43 61 6c 6c 62 61 63 6b } //01 00  RemoteCertificateValidationCallback
		$a_01_6 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_7 = {43 6c 69 65 6e 74 2e 49 6e 73 74 61 6c 6c } //01 00  Client.Install
		$a_01_8 = {4d 75 74 65 78 43 6f 6e 74 72 6f 6c } //01 00  MutexControl
		$a_01_9 = {44 65 74 65 63 74 44 65 62 75 67 67 65 72 } //01 00  DetectDebugger
		$a_01_10 = {43 6c 69 65 6e 74 2e 48 65 6c 70 65 72 } //01 00  Client.Helper
		$a_01_11 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_12 = {41 6e 74 69 5f 41 6e 61 6c 79 73 69 73 } //01 00  Anti_Analysis
		$a_01_13 = {49 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  ICredentials
		$a_01_14 = {41 6e 74 69 76 69 72 75 73 } //01 00  Antivirus
		$a_01_15 = {43 6c 69 65 6e 74 2e 48 61 6e 64 6c 65 5f 50 61 63 6b 65 74 } //01 00  Client.Handle_Packet
		$a_01_16 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_17 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //01 00  set_CreateNoWindow
		$a_01_18 = {5c 00 6e 00 75 00 52 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 65 00 72 00 61 00 77 00 74 00 66 00 6f 00 53 00 } //01 00  \nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_01_19 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //00 00  Select * from AntivirusProduct
	condition:
		any of ($a_*)
 
}