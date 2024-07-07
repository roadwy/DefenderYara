
rule Trojan_Win32_Fareit_RPY_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 db 90 8d 43 01 b9 93 00 00 00 33 d2 f7 f1 81 fa ff 00 00 00 } //1
		$a_01_1 = {8b c6 03 c3 88 10 89 c0 90 90 89 ff 43 81 fb 97 e7 6c 1f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}