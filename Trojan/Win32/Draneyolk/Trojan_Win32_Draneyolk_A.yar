
rule Trojan_Win32_Draneyolk_A{
	meta:
		description = "Trojan:Win32/Draneyolk.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e9 51 04 00 00 83 ff 6e 0f 87 dc 01 00 00 0f 84 cc 01 00 00 83 ff 2c 0f 87 ef 00 00 00 0f 84 df 00 00 00 83 ff 21 77 77 } //01 00 
		$a_01_1 = {5c 5c 2e 5c 4c 61 6e 64 72 69 76 65 31 5c 5c 6b 65 79 68 6f 6f 6b 2e 6c 6f 67 } //00 00  \\.\Landrive1\\keyhook.log
	condition:
		any of ($a_*)
 
}