
rule Trojan_Win32_Fragtor_GTK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {94 d0 ff b7 8f 57 28 26 b4 0f } //5
		$a_01_1 = {0f 91 c7 31 2c 24 5b 45 3b ea 48 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}