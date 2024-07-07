
rule HackTool_Win32_Racbot_A{
	meta:
		description = "HackTool:Win32/Racbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 20 52 2e 41 2e 43 20 5d 20 42 6f 74 20 47 65 6e 65 72 61 74 6f 72 } //1 [ R.A.C ] Bot Generator
		$a_01_1 = {5b 20 52 2e 41 2e 43 20 5d 20 28 52 65 6d 6f 74 65 20 41 69 6d 20 43 6f 6e 74 72 6f 6c 29 20 53 65 72 76 65 72 20 42 75 69 6c 64 65 72 } //1 [ R.A.C ] (Remote Aim Control) Server Builder
		$a_01_2 = {43 6d 64 42 6f 74 73 } //1 CmdBots
		$a_01_3 = {41 69 6d 50 61 73 73 } //1 AimPass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}