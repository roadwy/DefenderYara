
rule Trojan_Win32_TrickInj_A_MTB{
	meta:
		description = "Trojan:Win32/TrickInj.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5b 49 4e 49 54 5d 20 41 6c 69 76 65 20 3d 20 25 75 } //1 [INIT] Alive = %u
		$a_81_1 = {5b 49 4e 49 54 5d 20 49 6e 6a 20 3d 20 25 75 } //1 [INIT] Inj = %u
		$a_81_2 = {5b 49 4e 49 54 5d 20 42 43 20 3d 20 25 75 } //1 [INIT] BC = %u
		$a_81_3 = {23 70 67 69 64 23 } //1 #pgid#
		$a_81_4 = {69 6e 6a 5f 33 32 2e 64 6c 6c } //1 inj_32.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}