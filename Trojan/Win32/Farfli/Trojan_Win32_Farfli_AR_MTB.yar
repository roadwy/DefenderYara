
rule Trojan_Win32_Farfli_AR_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 11 32 54 45 e8 8b 45 08 03 45 d8 88 10 66 8b 4d e0 66 83 c1 01 66 89 4d e0 eb a9 } //2
		$a_01_1 = {43 3a 5c 69 6e 70 75 74 2e 74 78 74 } //2 C:\input.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}