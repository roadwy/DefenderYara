
rule Trojan_Win32_Inject_T{
	meta:
		description = "Trojan:Win32/Inject.T,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {80 3c 1e 66 75 29 80 7c 1e 01 24 75 22 80 7c 1e 02 47 75 1b 80 7c 1e 03 36 } //01 00 
		$a_03_1 = {0f b6 54 3a ff 33 55 f8 e8 90 01 02 ff ff 8b 55 f0 8b c6 e8 90 01 02 ff ff 47 4b 75 df 90 00 } //01 00 
		$a_03_2 = {80 ea 0d e8 90 01 02 ff ff 8b 55 f4 8b c6 e8 90 01 02 ff ff 47 8b 45 fc e8 90 01 02 ff ff 3b f8 7e c5 90 00 } //01 00 
		$a_03_3 = {eb 04 43 48 75 cd 85 ff 0f 90 01 02 01 00 00 e8 90 01 02 ff ff 84 c0 75 07 33 c0 e8 90 01 02 ff ff 6a 00 6a 00 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}