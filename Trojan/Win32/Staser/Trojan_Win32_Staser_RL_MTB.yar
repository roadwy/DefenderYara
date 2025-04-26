
rule Trojan_Win32_Staser_RL_MTB{
	meta:
		description = "Trojan:Win32/Staser.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 ff 15 34 66 65 00 6a 00 6a 00 ff 15 0c 63 65 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RL_MTB_2{
	meta:
		description = "Trojan:Win32/Staser.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3b 7d 0c a9 00 00 80 00 ff 75 14 e8 ?? 8f 06 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RL_MTB_3{
	meta:
		description = "Trojan:Win32/Staser.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 6a 01 56 ff 15 20 f0 46 00 56 ff 15 74 f0 46 00 ff 15 18 f0 46 00 e9 } //5
		$a_01_1 = {53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 ShutdownScheduler.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}