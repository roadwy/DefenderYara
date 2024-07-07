
rule Trojan_Win32_Staser_RM_MTB{
	meta:
		description = "Trojan:Win32/Staser.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a 00 6a 00 ff 15 78 f4 46 00 ff 15 70 f0 46 00 e9 } //5
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ShutdownScheduler.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}