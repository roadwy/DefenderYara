
rule Backdoor_Win32_PcClient_BC{
	meta:
		description = "Backdoor:Win32/PcClient.BC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 33 c0 e9 4b 0a 00 00 90 53 76 9b 58 68 ff 00 00 00 8b 45 08 05 42 04 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}