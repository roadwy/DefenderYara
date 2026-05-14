
rule Trojan_Win32_GuLoader_REJ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.REJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 65 73 6b 65 64 65 6e 73 20 63 6f 6c 64 62 6c 6f 6f 64 65 64 6e 65 73 73 20 61 72 72 61 69 67 6e 61 62 6c 65 } //1 beskedens coldbloodedness arraignable
		$a_81_1 = {73 75 6e 6b 65 74 73 20 68 6a 65 6d 6b 61 6c 64 65 72 } //1 sunkets hjemkalder
		$a_81_2 = {62 65 76 69 6c 6c 69 6e 67 73 68 61 76 65 72 20 61 62 61 6e 64 6f 6e 65 65 20 74 65 6c 74 } //1 bevillingshaver abandonee telt
		$a_81_3 = {63 68 65 72 63 6f 63 6b 20 62 61 69 72 64 69 2e 65 78 65 } //1 chercock bairdi.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}