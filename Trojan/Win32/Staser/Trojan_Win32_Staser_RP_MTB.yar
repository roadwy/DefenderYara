
rule Trojan_Win32_Staser_RP_MTB{
	meta:
		description = "Trojan:Win32/Staser.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 ff 15 ?? f0 46 00 8b 75 14 68 50 2c 27 01 56 ff 15 ?? f0 46 00 e9 } //5
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ShutdownScheduler.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}