
rule Backdoor_Win32_PcClient_CN{
	meta:
		description = "Backdoor:Win32/PcClient.CN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 75 74 64 6f 77 6e 68 61 6e 67 65 6c 2e 64 6c 6c 90 02 04 6c 75 6d 65 49 6e 66 6f 72 6c 90 02 04 44 7a 53 65 72 76 69 63 65 90 02 04 53 65 72 76 69 63 65 4d 61 69 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}