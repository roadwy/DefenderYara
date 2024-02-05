
rule Backdoor_Win32_PcClient_ZM{
	meta:
		description = "Backdoor:Win32/PcClient.ZM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {25 73 3d 00 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 90 02 06 2e 6b 65 79 90 02 06 2e 65 78 65 90 02 06 2e 90 04 03 03 61 2d 7a 00 90 02 06 2e 90 04 03 03 61 2d 7a 00 90 02 06 2e 90 02 10 25 73 25 30 35 78 2e 69 6d 69 90 02 06 47 6c 6f 62 61 6c 5c 70 73 25 30 36 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}