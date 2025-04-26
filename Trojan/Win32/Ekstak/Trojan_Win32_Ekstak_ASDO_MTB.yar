
rule Trojan_Win32_Ekstak_ASDO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 45 90 86 00 d8 14 83 00 00 1e 0a 00 06 0e ea } //5
		$a_01_1 = {2a 01 00 00 00 19 51 85 00 35 bc 81 00 00 ae 0a 00 23 97 } //5
		$a_01_2 = {2a 01 00 00 00 34 6c 73 00 ab d0 6f 00 00 be 0a 00 0b 33 49 b9 7c 56 6f 00 00 76 01 00 4b db } //5
		$a_01_3 = {2a 01 00 00 00 6e f5 7d 00 c7 d0 79 00 00 4c 0b 00 c1 20 b2 5d 6c a8 79 00 00 7c 01 } //5
		$a_01_4 = {2a 01 00 00 00 91 44 47 00 9a b6 43 00 00 96 0a 00 e4 91 6b 05 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=5
 
}