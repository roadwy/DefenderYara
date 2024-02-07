
rule Backdoor_Win32_Mdmbot_B{
	meta:
		description = "Backdoor:Win32/Mdmbot.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 61 73 6d 6f 6e 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //01 00  慒浳湯搮汬匀牥楶散慍湩
		$a_01_1 = {56 65 64 69 6f 44 72 69 76 65 72 2e 64 6c 6c } //01 00  VedioDriver.dll
		$a_01_2 = {5c 6d 64 6d 2e 65 78 65 } //01 00  \mdm.exe
		$a_01_3 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 53 75 6e 5c 31 2e 31 2e 32 } //00 00  Software\Sun\1.1.2
	condition:
		any of ($a_*)
 
}