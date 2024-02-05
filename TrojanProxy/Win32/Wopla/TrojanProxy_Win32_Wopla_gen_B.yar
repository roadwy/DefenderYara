
rule TrojanProxy_Win32_Wopla_gen_B{
	meta:
		description = "TrojanProxy:Win32/Wopla.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {74 0d 50 c7 00 a5 a5 a5 a5 ff 15 90 01 04 56 ff d3 e8 90 01 02 00 00 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {75 04 6a fd eb 19 38 5d 10 74 64 80 bd 90 01 02 ff ff 4d 75 09 80 bd 90 01 02 ff ff 5a 74 52 6a fc 8b 90 00 } //01 00 
		$a_01_2 = {99 b9 d0 07 00 00 f7 f9 04 61 88 04 3e 46 3b f3 7c e8 c6 04 1f 00 8b c7 } //01 00 
		$a_02_3 = {eb 64 38 5d 10 74 3f 80 bd 90 01 02 ff ff 4d 75 09 80 bd 90 01 02 ff ff 5a 74 2d 6a fc eb be 53 8d 45 f0 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}