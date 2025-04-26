
rule Trojan_Win32_Zusy_BT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6f 68 73 6f 70 72 6a 67 68 69 6f 72 6a 68 67 69 6f 72 6a } //2 Iohsoprjghiorjhgiorj
		$a_01_1 = {4c 6f 73 6f 73 6a 72 69 68 73 72 6a 68 69 73 6a 69 67 } //2 Lososjrihsrjhisjig
		$a_01_2 = {68 6a 73 67 69 73 65 67 6a 6f 69 67 68 6a 73 65 69 68 65 } //2 hjsgisegjoighjseihe
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}