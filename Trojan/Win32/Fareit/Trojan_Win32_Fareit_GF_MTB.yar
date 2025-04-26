
rule Trojan_Win32_Fareit_GF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.GF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {36 30 2e 64 6c 6c 00 ba db 00 51 d4 d0 20 ee d2 4e dc 74 } //1
		$a_01_1 = {46 f5 2b 48 34 6e c1 0b 30 66 da c0 51 5b fa 1a 79 a0 6d 09 f0 f3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}