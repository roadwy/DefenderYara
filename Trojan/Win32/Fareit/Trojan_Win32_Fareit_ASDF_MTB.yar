
rule Trojan_Win32_Fareit_ASDF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.ASDF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3e b9 a6 07 f4 0f 34 21 38 e4 fc 2f 5a 97 79 f4 } //1
		$a_01_1 = {38 7e 45 d2 ac 34 71 09 30 1c 11 c4 32 5c 76 4a 8d ab 46 6d 1c 98 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}