
rule TrojanDropper_Win32_Fainli_A{
	meta:
		description = "TrojanDropper:Win32/Fainli.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 44 24 0c 20 ff 4c 24 14 0f 85 e2 fe ff ff } //1
		$a_01_1 = {8b 44 24 0c 6a 0a 83 c0 04 50 53 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}