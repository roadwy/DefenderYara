
rule TrojanClicker_BAT_Youclick_A{
	meta:
		description = "TrojanClicker:BAT/Youclick.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 74 75 62 65 42 72 6f 77 73 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //3 YoutubeBrowser.Form1.resources
		$a_01_1 = {49 00 6e 00 65 00 74 00 43 00 70 00 6c 00 2e 00 63 00 70 00 6c 00 2c 00 43 00 6c 00 65 00 61 00 72 00 4d 00 79 00 54 00 72 00 61 00 63 00 6b 00 73 00 42 00 79 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 34 00 33 00 35 00 31 00 } //3 InetCpl.cpl,ClearMyTracksByProcess 4351
		$a_01_2 = {2f 00 62 00 61 00 63 00 6b 00 67 00 6f 00 75 00 6e 00 64 00 2f 00 69 00 6d 00 67 00 2f 00 6c 00 69 00 6e 00 6b 00 30 00 2e 00 70 00 68 00 70 00 } //1 /backgound/img/link0.php
		$a_01_3 = {5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 73 77 68 6f 73 74 2e 70 64 62 } //3 \x86\Release\swhost.pdb
		$a_01_4 = {2f 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2f 00 49 00 4d 00 47 00 2f 00 75 00 73 00 65 00 72 00 5f 00 61 00 67 00 65 00 6e 00 74 00 2e 00 70 00 68 00 70 00 } //1 /background/IMG/user_agent.php
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=7
 
}