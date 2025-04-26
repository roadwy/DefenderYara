
rule Trojan_Win64_TrickInj_A_MTB{
	meta:
		description = "Trojan:Win64/TrickInj.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {69 6e 6a 5f 36 34 2e 64 6c 6c } //inj_64.dll  1
		$a_80_1 = {5b 49 4e 49 54 5d 20 49 6e 6a 20 3d 20 25 75 } //[INIT] Inj = %u  1
		$a_80_2 = {5b 49 4e 49 54 5d 20 42 43 20 3d 20 25 75 } //[INIT] BC = %u  1
		$a_80_3 = {5b 49 4e 49 54 5d 20 50 72 6f 78 79 20 3d 20 25 75 } //[INIT] Proxy = %u  1
		$a_80_4 = {23 70 67 69 64 23 } //#pgid#  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}