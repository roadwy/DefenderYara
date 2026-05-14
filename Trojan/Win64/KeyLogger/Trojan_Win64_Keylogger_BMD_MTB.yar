
rule Trojan_Win64_Keylogger_BMD_MTB{
	meta:
		description = "Trojan:Win64/Keylogger.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 70 65 72 5f 6d 61 69 6e 5f 32 35 5c 4d 69 63 72 6f 73 6f 66 74 4d 69 67 72 61 74 69 6f 6e 5c 68 61 6e 64 79 63 61 66 65 49 6e 73 74 61 6c 6c 65 72 5c 62 72 73 65 72 76 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4b 59 2e 70 64 62 } //2 C:\per_main_25\MicrosoftMigration\handycafeInstaller\brserver\x64\Release\KY.pdb
	condition:
		((#a_01_0  & 1)*2) >=2
 
}