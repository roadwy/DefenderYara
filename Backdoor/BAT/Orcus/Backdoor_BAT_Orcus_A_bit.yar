
rule Backdoor_BAT_Orcus_A_bit{
	meta:
		description = "Backdoor:BAT/Orcus.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 72 63 75 73 2e 50 72 6f 74 65 63 74 69 6f 6e } //01 00  Orcus.Protection
		$a_01_1 = {4f 72 63 75 73 2e 50 6c 75 67 69 6e 73 } //01 00  Orcus.Plugins
		$a_01_2 = {4f 72 63 75 73 2e 4e 61 74 69 76 65 2e 53 68 65 6c 6c } //01 00  Orcus.Native.Shell
		$a_01_3 = {4f 72 63 75 73 2e 55 74 69 6c 69 74 69 65 73 2e 4b 65 79 4c 6f 67 67 65 72 } //01 00  Orcus.Utilities.KeyLogger
		$a_01_4 = {4f 72 63 75 73 2e 43 6f 6d 6d 61 6e 64 73 2e 52 65 6d 6f 74 65 44 65 73 6b 74 6f 70 2e 43 61 70 74 75 72 65 } //01 00  Orcus.Commands.RemoteDesktop.Capture
		$a_01_5 = {4f 72 63 75 73 2e 43 6f 6d 6d 61 6e 64 73 2e 44 72 6f 70 41 6e 64 45 78 65 63 75 74 65 } //01 00  Orcus.Commands.DropAndExecute
		$a_01_6 = {4f 72 63 75 73 2e 53 68 61 72 65 64 2e 43 6f 6d 6d 61 6e 64 73 2e 57 65 62 63 61 6d } //00 00  Orcus.Shared.Commands.Webcam
	condition:
		any of ($a_*)
 
}