
rule Trojan_BAT_Starter_KAA_MTB{
	meta:
		description = "Trojan:BAT/Starter.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 68 00 6f 00 73 00 74 00 64 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  /hostdl.exe
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //01 00  GetProcessesByName
		$a_01_2 = {55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00  UseShellExecute
	condition:
		any of ($a_*)
 
}