
rule Trojan_Win32_Staser_RQ_MTB{
	meta:
		description = "Trojan:Win32/Staser.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 68 50 3c 27 01 56 ff 15 68 f0 46 00 56 ff 15 5c f6 46 00 6a 00 6a 00 ff 15 58 f6 46 00 } //01 00 
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  ShutdownScheduler.exe
	condition:
		any of ($a_*)
 
}