
rule Trojan_Win32_Nanocore_GPE_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 23 61 23 43 68 56 00 44 23 61 23 43 68 56 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad } //5
		$a_01_1 = {54 23 04 20 68 20 11 32 54 23 04 20 68 20 11 32 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}