
rule Worm_Win32_Autorun_KC{
	meta:
		description = "Worm:Win32/Autorun.KC,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 04 00 00 "
		
	strings :
		$a_02_0 = {5c 52 75 6e [0-08] 48 6f 6f 6b 50 72 6f 63 2e 64 6c 6c [0-04] 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //10
		$a_02_1 = {48 69 64 65 51 51 [0-04] 48 6f 6f 6b 50 72 6f 63 } //10
		$a_00_2 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d } //5 shell\explore\Command=
		$a_00_3 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1) >=26
 
}