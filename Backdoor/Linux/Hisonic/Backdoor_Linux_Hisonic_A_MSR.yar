
rule Backdoor_Linux_Hisonic_A_MSR{
	meta:
		description = "Backdoor:Linux/Hisonic.A!MSR,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 28 2a 53 65 72 76 69 63 65 29 2e 48 74 74 70 43 6d 64 } //1 main.(*Service).HttpCmd
		$a_01_1 = {6d 61 69 6e 2e 28 2a 53 65 72 76 69 63 65 29 2e 48 74 74 70 50 69 6e 67 } //1 main.(*Service).HttpPing
		$a_01_2 = {43 6d 64 53 52 75 6e 43 6f 64 65 } //1 CmdSRunCode
		$a_01_3 = {43 6d 64 43 52 75 6e 43 6d 64 52 65 73 75 6c 74 } //1 CmdCRunCmdResult
		$a_01_4 = {43 6d 64 53 53 77 69 74 63 68 54 43 50 } //1 CmdSSwitchTCP
		$a_01_5 = {28 2a 53 52 75 6e 43 6d 64 29 2e 47 65 74 41 72 67 73 } //1 (*SRunCmd).GetArgs
		$a_01_6 = {28 2a 43 6d 64 43 50 69 6e 67 43 69 64 29 2e 52 65 61 64 42 79 74 65 73 } //1 (*CmdCPingCid).ReadBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}