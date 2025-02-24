
rule Trojan_Win32_Bayrob_MX_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 ca 39 d0 7d 0c 81 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bayrob_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Bayrob.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 09 53 e8 6e 85 ff ff 59 33 db 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bayrob_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Bayrob.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 c0 75 08 6a 1c e8 22 01 00 00 59 e8 d5 25 00 00 85 c0 75 08 6a 10 e8 11 01 00 00 59 } //1
		$a_01_1 = {59 85 c0 74 07 50 e8 ea fb ff ff 59 e8 f1 68 00 00 56 50 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}