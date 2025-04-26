
rule Trojan_Win32_Remcos_CAA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.CAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 db 53 53 53 54 6a 00 c7 04 24 00 20 04 00 52 51 54 } //4
		$a_01_1 = {83 ec 1c d9 e4 d9 34 24 8b 74 24 0c 83 c6 10 83 c4 1c c3 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}