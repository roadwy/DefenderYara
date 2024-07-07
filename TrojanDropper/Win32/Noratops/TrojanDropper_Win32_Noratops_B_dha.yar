
rule TrojanDropper_Win32_Noratops_B_dha{
	meta:
		description = "TrojanDropper:Win32/Noratops.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {c1 e3 06 03 df 8b bd e8 fd ff ff c1 e3 06 03 d8 3b 90 01 01 73 4c 90 00 } //1
		$a_01_1 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
		$a_01_2 = {49 6e 6a 65 63 74 6f 72 2e 64 6c 6c } //1 Injector.dll
		$a_01_3 = {5f 64 65 63 } //1 _dec
		$a_01_4 = {5f 5f 64 65 63 } //1 __dec
		$a_01_5 = {56 00 25 00 64 00 00 00 } //1
		$a_01_6 = {49 00 4e 00 46 00 4f 00 } //1 INFO
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}