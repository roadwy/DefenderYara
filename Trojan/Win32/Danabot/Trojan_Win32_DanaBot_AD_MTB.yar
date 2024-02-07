
rule Trojan_Win32_DanaBot_AD_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 3e 56 90 02 30 83 c4 90 02 20 8b f0 85 f6 90 02 c8 8b 8d 90 02 40 33 cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_DanaBot_AD_MTB_2{
	meta:
		description = "Trojan:Win32/DanaBot.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 72 6f 77 64 65 64 34 2e 64 6c 6c } //01 00  crowded4.dll
		$a_01_1 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_01_2 = {54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 } //01 00  TMethodImplementationIntercept
		$a_00_3 = {53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 45 00 78 00 57 00 } //01 00  ShellExecuteExW
		$a_00_4 = {50 00 67 00 5a 00 4e 00 54 00 50 00 67 00 58 00 51 00 54 00 70 00 } //01 00  PgZNTPgXQTp
		$a_00_5 = {43 00 3a 00 5c 00 6d 00 79 00 73 00 65 00 6c 00 66 00 2e 00 64 00 6c 00 6c 00 } //00 00  C:\myself.dll
	condition:
		any of ($a_*)
 
}