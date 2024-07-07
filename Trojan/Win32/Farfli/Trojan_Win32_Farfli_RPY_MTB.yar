
rule Trojan_Win32_Farfli_RPY_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 1e 29 c0 46 29 c0 47 39 ce 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Farfli_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c0 31 37 01 db 81 c7 01 00 00 00 39 d7 75 e0 21 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Farfli_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 fe 29 ff 8d 04 02 8b 00 81 c7 01 00 00 00 81 e0 ff 00 00 00 81 c2 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Farfli_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/Farfli.RPY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 8d 45 fc 50 ff 36 ff d3 3d 0d 00 00 c0 74 24 83 c6 04 83 c7 10 81 fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}