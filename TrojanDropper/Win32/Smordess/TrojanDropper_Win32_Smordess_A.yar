
rule TrojanDropper_Win32_Smordess_A{
	meta:
		description = "TrojanDropper:Win32/Smordess.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f a2 0f 31 4e 75 f9 } //1
		$a_01_1 = {69 67 66 78 65 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}