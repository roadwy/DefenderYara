
rule Trojan_BAT_Fbtaken_EB_MTB{
	meta:
		description = "Trojan:BAT/Fbtaken.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 50 6c 75 73 53 63 68 65 64 75 6c 65 72 2e 65 78 65 } //01 00  FPlusScheduler.exe
		$a_01_1 = {44 65 66 61 75 6c 74 4c 6f 67 67 65 72 } //01 00  DefaultLogger
		$a_01_2 = {46 69 6c 65 4c 6f 67 67 65 72 } //01 00  FileLogger
		$a_01_3 = {52 65 6e 63 69 2e 53 73 68 4e 65 74 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 43 69 70 68 65 72 73 2e 4d 6f 64 65 73 } //01 00  Renci.SshNet.Security.Cryptography.Ciphers.Modes
		$a_01_4 = {53 32 32 2e 49 6d 61 70 2e 41 75 74 68 2e 53 61 73 6c 2e 4d 65 63 68 61 6e 69 73 6d 73 } //00 00  S22.Imap.Auth.Sasl.Mechanisms
	condition:
		any of ($a_*)
 
}