
rule Trojan_Win32_Zusy_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 4b 80 61 4b 80 e4 af f3 9a a5 e4 9c 83 be 8c 43 80 b1 97 c4 49 a6 ac a6 e4 e4 af f3 9a a5 e4 9c 83 be 8c 43 80 b1 97 c4 49 a6 ac a6 e4 } //1
		$a_01_1 = {1b 11 00 fb 30 1c 08 02 27 04 ff 27 3c ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}