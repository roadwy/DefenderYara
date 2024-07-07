
rule Backdoor_Win32_Frocat_A_MTB{
	meta:
		description = "Backdoor:Win32/Frocat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {28 2a 41 50 49 29 2e 53 68 72 65 64 } //1 (*API).Shred
		$a_01_1 = {28 2a 41 50 49 29 2e 47 6f 6d 61 70 } //1 (*API).Gomap
		$a_01_2 = {28 2a 41 50 49 29 2e 53 70 65 65 64 74 65 73 74 } //1 (*API).Speedtest
		$a_01_3 = {28 2a 41 50 49 29 2e 53 63 72 65 65 6e } //1 (*API).Screen
		$a_01_4 = {28 2a 41 50 49 29 2e 52 65 63 6f 6e 6e 65 63 74 } //1 (*API).Reconnect
		$a_01_5 = {28 2a 41 50 49 29 2e 4e 65 77 48 6f 73 74 6e 61 6d 65 } //1 (*API).NewHostname
		$a_01_6 = {28 2a 41 50 49 29 2e 52 75 6e 43 6d 64 } //1 (*API).RunCmd
		$a_01_7 = {28 2a 41 50 49 29 2e 53 65 6e 64 46 69 6c 65 } //1 (*API).SendFile
		$a_01_8 = {28 2a 41 50 49 29 2e 52 65 63 76 46 69 6c 65 } //1 (*API).RecvFile
		$a_01_9 = {28 2a 41 50 49 29 2e 47 65 74 48 61 72 64 77 61 72 65 } //1 (*API).GetHardware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}