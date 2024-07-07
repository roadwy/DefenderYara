
rule Trojan_Win32_DllInject_SP_MTB{
	meta:
		description = "Trojan:Win32/DllInject.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {4a 6a 61 69 65 66 68 61 64 75 69 67 65 68 68 67 64 68 64 } //1 Jjaiefhaduigehhgdhd
		$a_81_1 = {6b 61 6b 66 67 6a 61 65 69 6f 67 6a 64 73 69 6a } //1 kakfgjaeiogjdsij
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}