
rule Trojan_Win32_AsyncRAT_ARAQ_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.ARAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {37 3e 5c 2b 44 37 72 34 28 71 48 63 40 33 77 39 35 27 44 64 29 67 75 74 4a 24 2e 72 65 73 6f 75 72 63 65 73 } //10 7>\+D7r4(qHc@3w95'Dd)gutJ$.resources
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //2 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}