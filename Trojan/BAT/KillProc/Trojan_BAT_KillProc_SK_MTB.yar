
rule Trojan_BAT_KillProc_SK_MTB{
	meta:
		description = "Trojan:BAT/KillProc.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {17 8d 1a 00 00 01 13 07 11 07 16 72 23 00 00 70 a2 11 07 73 1f 00 00 0a 0c } //02 00 
		$a_01_1 = {11 0a 11 09 9a 13 05 11 05 6f 23 00 00 0a 09 28 24 00 00 0a 6f 25 00 00 0a 2c 07 11 05 6f 26 00 00 0a 11 09 17 d6 13 09 11 09 11 0a 8e b7 32 d0 } //02 00 
		$a_01_2 = {50 61 79 6c 6f 61 64 2e 65 78 65 } //00 00  Payload.exe
	condition:
		any of ($a_*)
 
}