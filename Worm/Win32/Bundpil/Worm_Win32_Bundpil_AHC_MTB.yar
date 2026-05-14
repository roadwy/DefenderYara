
rule Worm_Win32_Bundpil_AHC_MTB{
	meta:
		description = "Worm:Win32/Bundpil.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 d8 88 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? b1 ?? f6 e9 4e a2 ?? ?? ?? ?? 75 } //30
		$a_01_1 = {6b 49 69 43 63 41 61 79 58 72 56 52 64 73 44 6d 75 68 71 6e 6d 6c 64 6d 73 55 } //20 kIiCcAayXrVRdsDmuhqnmldmsU
		$a_01_2 = {63 78 61 71 55 6a 64 71 6d 64 6b 32 31 7c 4f 72 4d 6d 6d 48 68 42 65 } //10 cxaqUjdqmdk21|OrMmmHhBe
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}