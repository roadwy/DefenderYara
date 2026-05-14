
rule Trojan_Win32_Neoreblamy_NUC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 08 58 6b c0 00 8d 44 05 9c 6a 04 59 c1 e1 00 } //2
		$a_01_1 = {7c ea 8b 45 fc 33 db 8b 45 fc 43 39 75 fc } //2
		$a_01_2 = {7c e6 ff 45 f4 39 7d f4 7c d9 89 5d f4 eb 0e 8b 45 f4 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}