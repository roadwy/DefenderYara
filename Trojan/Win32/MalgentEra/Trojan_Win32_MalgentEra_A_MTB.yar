
rule Trojan_Win32_MalgentEra_A_MTB{
	meta:
		description = "Trojan:Win32/MalgentEra.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 f4 83 79 1c 01 89 55 f8 75 4d 57 8b 79 0c 85 ff 74 2e 8b ca 56 0f b7 34 53 8d 46 d0 83 f8 09 77 19 66 89 74 0d f4 83 c1 02 83 f9 08 73 38 33 c0 66 89 44 0d f4 83 f9 06 74 05 42 3b d7 72 d6 5e 68 } //1
		$a_81_1 = {65 76 61 6c 28 } //1 eval(
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}