
rule Trojan_Win32_DarkGate_KKM_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.KKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 f7 f3 c5 fd 62 c3 c5 e5 6a dc 8a 04 16 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef 30 04 0f c5 e5 60 dd 41 c5 c5 73 d8 ?? 89 c8 81 f9 07 74 17 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}