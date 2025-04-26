
rule Trojan_AndroidOS_Xhunter_A{
	meta:
		description = "Trojan:AndroidOS/Xhunter.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 78 68 75 6e 74 65 72 2e 63 6c 69 65 6e 74 } //2 com.xhunter.client
		$a_01_1 = {3c 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 3e 3c 3e 3c 3e 3e 3c 3c 3c 3c 3e 53 75 63 63 65 73 73 66 75 6c 6c 79 20 73 74 61 72 74 65 64 20 6d 79 73 65 6c 66 2b 2b 2b 2b 3e 3e 3e 3e 3e 3e 3e 3e } //2 <++++++++++++++++><><>><<<<>Successfully started myself++++>>>>>>>>
		$a_01_2 = {78 68 75 6e 74 65 72 54 65 73 74 } //2 xhunterTest
		$a_01_3 = {7b 22 74 65 78 74 22 3a 22 56 69 63 74 69 6d 20 } //2 {"text":"Victim 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}