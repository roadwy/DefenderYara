
rule Backdoor_Win32_Agent_GJ{
	meta:
		description = "Backdoor:Win32/Agent.GJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 30 32 68 75 2d 25 30 32 68 75 2d 25 68 75 5f 25 30 32 68 75 2d 25 30 32 68 75 2d 25 30 32 68 75 5f 25 73 } //01 00  %02hu-%02hu-%hu_%02hu-%02hu-%02hu_%s
		$a_01_1 = {55 53 42 5f 46 69 6c 65 5f 52 61 74 5f } //01 00  USB_File_Rat_
		$a_00_2 = {52 65 67 69 73 74 72 79 2d 47 72 61 62 62 69 6e 67 2e 72 65 67 } //01 00  Registry-Grabbing.reg
		$a_01_3 = {52 45 4d 4f 56 41 42 4c 45 00 46 49 58 45 44 } //00 00 
	condition:
		any of ($a_*)
 
}