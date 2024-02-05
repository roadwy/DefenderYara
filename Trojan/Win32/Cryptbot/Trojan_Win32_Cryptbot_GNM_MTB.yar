
rule Trojan_Win32_Cryptbot_GNM_MTB{
	meta:
		description = "Trojan:Win32/Cryptbot.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b ce 81 c0 27 fa 2b d4 33 c6 83 c0 53 89 45 f0 } //01 00 
		$a_01_1 = {4a 76 45 71 79 28 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00 
		$a_01_2 = {5d 6b 56 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00 
		$a_01_3 = {24 38 4a 76 45 71 79 28 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00 
		$a_01_4 = {59 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}