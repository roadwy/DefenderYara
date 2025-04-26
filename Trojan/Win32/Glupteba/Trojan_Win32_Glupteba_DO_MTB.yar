
rule Trojan_Win32_Glupteba_DO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 ca 57 29 ca 5e 81 e9 e8 53 9f 3a 43 81 e9 21 2a e5 23 41 81 c2 8b 9e 80 ab 81 fb f3 e4 00 01 75 } //2
		$a_01_1 = {31 1a 42 21 cf 29 ff 39 c2 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}