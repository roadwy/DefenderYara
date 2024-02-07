
rule Trojan_Win32_Dridex_NM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 75 62 65 4c 6e 74 65 73 74 69 6e 67 79 52 70 70 65 72 66 6f 72 6d 65 64 } //01 00  VubeLntestingyRpperformed
		$a_81_1 = {6f 6e 50 68 69 64 64 65 6e 6e 65 77 } //01 00  onPhiddennew
		$a_81_2 = {48 69 6a 61 6d 65 73 6f 6e 77 } //01 00  Hijamesonw
		$a_81_3 = {73 74 61 72 74 65 64 62 71 65 6e 67 69 6e 65 } //01 00  startedbqengine
		$a_81_4 = {74 79 70 69 6e 67 37 66 6f 72 53 6f 6d 65 } //01 00  typing7forSome
		$a_81_5 = {74 68 65 6d 2e 31 36 35 74 68 69 72 64 4d 61 69 6e 7a 35 62 42 } //05 00  them.165thirdMainz5bB
		$a_02_6 = {89 ca 83 e2 90 01 01 8b 90 02 06 8a 90 02 02 2a 90 02 06 00 e0 88 90 02 02 83 90 02 06 89 90 02 0d 39 90 01 01 90 18 b0 90 01 01 8b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}