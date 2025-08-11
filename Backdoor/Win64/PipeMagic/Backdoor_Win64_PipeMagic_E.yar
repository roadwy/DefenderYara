
rule Backdoor_Win64_PipeMagic_E{
	meta:
		description = "Backdoor:Win64/PipeMagic.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 03 d0 c1 fa 07 8b ca c1 e9 1f 03 d1 69 ca ff 00 00 ?? 44 2b c1 44 88 04 03 48 03 df 48 83 fb 10 } //1
		$a_01_1 = {41 0f b6 00 49 ff c0 8b c8 48 c1 e8 04 83 e1 0f 42 8a 04 18 88 02 48 8d 52 02 42 8a 04 19 88 42 ff 41 83 c1 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}