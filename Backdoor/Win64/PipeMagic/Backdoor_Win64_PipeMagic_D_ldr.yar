
rule Backdoor_Win64_PipeMagic_D_ldr{
	meta:
		description = "Backdoor:Win64/PipeMagic.D!ldr,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 08 41 30 14 08 48 8d 51 01 48 89 d1 48 83 fa 10 75 } //1
		$a_03_1 = {c1 e6 18 c1 e7 10 41 c1 e3 08 41 09 cb 41 09 fb 48 89 df 41 09 f3 41 8b 48 ?? 0f c9 44 31 d9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}