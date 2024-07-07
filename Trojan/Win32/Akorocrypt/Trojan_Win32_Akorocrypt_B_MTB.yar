
rule Trojan_Win32_Akorocrypt_B_MTB{
	meta:
		description = "Trojan:Win32/Akorocrypt.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 57 6a 00 ff 15 } //1
		$a_01_1 = {80 74 05 ac bc 40 83 f8 14 72 f5 } //1
		$a_03_2 = {8b c2 33 d2 f7 f1 8a 44 15 90 01 01 42 30 04 90 01 04 72 ed 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}