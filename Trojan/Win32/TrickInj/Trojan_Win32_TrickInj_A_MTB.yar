
rule Trojan_Win32_TrickInj_A_MTB{
	meta:
		description = "Trojan:Win32/TrickInj.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {5b 49 4e 49 54 5d 20 41 6c 69 76 65 20 3d 20 25 75 } //01 00  [INIT] Alive = %u
		$a_81_1 = {5b 49 4e 49 54 5d 20 49 6e 6a 20 3d 20 25 75 } //01 00  [INIT] Inj = %u
		$a_81_2 = {5b 49 4e 49 54 5d 20 42 43 20 3d 20 25 75 } //01 00  [INIT] BC = %u
		$a_81_3 = {23 70 67 69 64 23 } //01 00  #pgid#
		$a_81_4 = {69 6e 6a 5f 33 32 2e 64 6c 6c } //00 00  inj_32.dll
	condition:
		any of ($a_*)
 
}