
rule Backdoor_Win32_Farfli_BF_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75 } //1
		$a_01_1 = {c6 44 24 19 44 c6 44 24 1a 56 c6 44 24 1c 50 c6 44 24 1d 49 c6 44 24 1e 33 c6 44 24 1f 32 c6 44 24 20 2e c6 44 24 21 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}