
rule PWS_Win32_Peerfit_gen_A{
	meta:
		description = "PWS:Win32/Peerfit.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 7d f0 00 74 08 8b 45 f0 e8 ?? ?? ?? ?? 33 c0 } //1
		$a_03_1 = {8b 40 50 50 6a 00 6a ff e8 ?? ?? ?? ?? 8b f0 8b 45 f8 8b 48 54 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}