
rule Trojan_Win32_Androm_EM_MTB{
	meta:
		description = "Trojan:Win32/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 98 30 80 40 00 32 d9 88 98 30 80 40 00 40 83 f8 08 7c ec } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Androm_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b fb c1 e9 02 f3 a5 8b ca 83 e1 03 85 c0 f3 a4 75 0b 5f 5e 5d 5b 81 c4 04 06 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Androm_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Androm.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f8 8b d1 81 c6 90 da 04 00 8b df c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 5f 5e 85 db 5b 75 03 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}