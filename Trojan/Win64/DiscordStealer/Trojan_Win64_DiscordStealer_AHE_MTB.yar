
rule Trojan_Win64_DiscordStealer_AHE_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 5c 53 79 73 43 66 67 } //20 Microsoft\SysCfg
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 2f 62 20 22 22 20 22 25 73 } //30 cmd.exe /c start /b "" "%s
		$a_01_2 = {53 79 73 43 66 67 53 76 63 } //40 SysCfgSvc
		$a_01_3 = {4c 89 6c 24 30 4c 0f 43 64 24 70 48 8d 7c 24 30 be 0f 00 00 00 4c 89 6c 24 40 4c 89 6c 24 48 4c 3b fe 76 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30+(#a_01_2  & 1)*40+(#a_01_3  & 1)*10) >=100
 
}