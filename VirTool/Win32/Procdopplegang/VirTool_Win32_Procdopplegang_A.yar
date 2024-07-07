
rule VirTool_Win32_Procdopplegang_A{
	meta:
		description = "VirTool:Win32/Procdopplegang.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 6a 04 68 00 30 00 00 8b b0 90 01 01 02 00 00 03 30 56 50 ff 75 f0 ff 90 01 05 8b 45 ec 6a 00 56 8b 35 00 30 40 00 50 50 ff 75 f0 ff 90 01 01 85 c0 90 01 02 ff 90 00 } //1
		$a_03_1 = {83 ec 3c a1 90 01 04 33 c5 89 45 fc 53 56 57 6a 00 6a 00 6a 00 8b da 89 4d d0 53 6a 04 ff 90 01 05 50 6a 00 68 ff ff 1f 00 90 01 03 50 ff 90 00 } //1
		$a_03_2 = {6a 00 6a 00 6a 00 57 6a 00 6a 00 ff 75 f0 ff 90 01 05 8b f8 85 ff 90 01 02 ff 90 01 05 50 90 01 05 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}