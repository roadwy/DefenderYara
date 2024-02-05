
rule Backdoor_Win32_PcClient_ZD{
	meta:
		description = "Backdoor:Win32/PcClient.ZD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 83 f8 05 74 3b c6 45 b8 64 c6 45 b9 6d 90 90 90 c6 45 ba 73 c6 45 bb 65 90 c6 45 bc 72 c6 45 bd 76 c6 45 be 65 c6 45 bf 72 c6 45 c0 2e 90 c6 45 c1 64 c6 45 c2 6c c6 45 c3 6c 80 65 c4 00 eb 2e c6 45 b8 72 c6 45 b9 70 90 c6 45 ba 63 c6 45 bb 73 90 c6 45 bc 73 c6 45 bd 2e 90 90 90 c6 45 be 64 c6 45 bf 6c 90 c6 45 c0 6c } //00 00 
	condition:
		any of ($a_*)
 
}