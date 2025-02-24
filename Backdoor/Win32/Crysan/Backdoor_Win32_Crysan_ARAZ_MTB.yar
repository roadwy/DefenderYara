
rule Backdoor_Win32_Crysan_ARAZ_MTB{
	meta:
		description = "Backdoor:Win32/Crysan.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {67 69 6e 65 20 53 68 69 65 6c 64 65 6e 20 76 32 2e 34 2e 30 2e 30 00 eb 25 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}