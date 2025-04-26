
rule Trojan_Win32_Turla{
	meta:
		description = "Trojan:Win32/Turla,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d4 48 00 65 00 c7 45 d8 6c 00 70 00 c7 45 dc 41 00 73 00 c7 45 e0 73 00 69 00 c7 45 e4 73 00 74 00 c7 45 e8 61 00 6e 00 c7 45 ec 74 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}