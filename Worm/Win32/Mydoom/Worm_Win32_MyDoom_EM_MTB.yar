
rule Worm_Win32_MyDoom_EM_MTB{
	meta:
		description = "Worm:Win32/MyDoom.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 76 69 6c 32 31 30 30 } //01 00  devil2100
		$a_01_1 = {73 68 61 69 62 32 30 30 } //01 00  shaib200
		$a_01_2 = {61 6c 6d 61 37 72 6f 6f 6d 6d } //01 00  alma7roomm
		$a_01_3 = {6a 61 73 69 6d 38 31 30 } //01 00  jasim810
		$a_01_4 = {77 61 72 72 65 72 5f 35 30 } //01 00  warrer_50
		$a_01_5 = {6d 6f 68 61 6d 6d 65 64 30 30 37 } //01 00  mohammed007
		$a_01_6 = {72 61 68 2e 70 6f 6c 61 6b 61 } //01 00  rah.polaka
		$a_01_7 = {73 73 6b 65 72 61 6c 65 78 61 6e 64 65 72 } //01 00  sskeralexander
		$a_01_8 = {61 6d 62 61 74 75 6b 61 6d } //00 00  ambatukam
	condition:
		any of ($a_*)
 
}