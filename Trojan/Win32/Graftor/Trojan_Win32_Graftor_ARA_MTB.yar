
rule Trojan_Win32_Graftor_ARA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 5c 04 10 80 f3 1a 88 5c 04 10 40 83 f8 05 72 ef } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Graftor_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Graftor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 10 8a 14 1a 8b 4d 10 30 14 31 ff 00 39 38 75 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}