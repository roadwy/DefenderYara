
rule Trojan_Win32_Sfuzuan_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Sfuzuan.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 6f 77 6e 2e 68 6a 6b 6c 34 35 36 37 38 2e 78 79 7a } //1 down.hjkl45678.xyz
		$a_81_1 = {39 63 38 30 30 37 62 33 36 33 63 30 63 33 30 35 37 38 65 63 35 34 62 38 30 31 33 37 39 32 33 61 64 39 62 31 34 34 62 31 34 34 30 65 38 31 64 34 } //1 9c8007b363c0c30578ec54b80137923ad9b144b1440e81d4
		$a_81_2 = {32 62 6b 65 37 61 62 34 33 63 38 31 62 73 36 36 33 36 63 6c 36 35 35 63 7a 63 65 33 39 62 63 74 } //1 2bke7ab43c81bs6636cl655czce39bct
		$a_81_3 = {63 38 32 33 39 33 32 33 34 65 61 32 39 32 31 65 66 65 36 62 30 61 63 33 35 30 31 33 32 61 64 65 } //1 c82393234ea2921efe6b0ac350132ade
		$a_81_4 = {32 32 33 2e 35 2e 35 2e 35 2f 72 65 73 6f 6c 76 65 3f 6e 61 6d 65 3d 25 73 } //1 223.5.5.5/resolve?name=%s
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}