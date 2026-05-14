
rule Trojan_Win64_DiscordStealer_MK_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 70 74 75 72 69 6e 67 20 63 6c 69 70 62 6f 61 72 64 20 63 6f 6e 74 65 6e 74 2e 2e 2e } //20 Capturing clipboard content...
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 4d 69 63 72 6f 73 6f 66 74 45 64 67 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 22 20 2f 74 72 20 22 5c 22 } //15 cmd.exe /c schtasks /create /tn "MicrosoftEdgeUpdateTaskMachine" /tr "\"
		$a_01_2 = {54 61 73 6b 20 6e 6f 74 20 66 6f 75 6e 64 2c 20 75 73 69 6e 67 20 55 41 43 20 62 79 70 61 73 73 20 74 6f 20 63 72 65 61 74 65 2e 2e 2e } //10 Task not found, using UAC bypass to create...
		$a_01_3 = {48 54 4d 4c 20 64 61 74 61 20 63 61 70 74 75 72 65 64 } //5 HTML data captured
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=50
 
}