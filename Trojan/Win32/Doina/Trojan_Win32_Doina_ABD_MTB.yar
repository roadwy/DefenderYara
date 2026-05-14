
rule Trojan_Win32_Doina_ABD_MTB{
	meta:
		description = "Trojan:Win32/Doina.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 36 32 2e 36 30 2e 32 32 36 2e 31 35 39 2f [0-0f] 2e 65 78 65 } //1
		$a_81_1 = {47 6c 6f 62 61 6c 5c 64 73 66 64 73 6f 69 6a 62 76 6f 78 69 55 48 55 6f 6b 70 6f 43 56 53 39 58 56 46 38 34 38 } //1 Global\dsfdsoijbvoxiUHUokpoCVS9XVF848
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}