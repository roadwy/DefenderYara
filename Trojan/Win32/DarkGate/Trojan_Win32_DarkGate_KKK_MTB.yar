
rule Trojan_Win32_DarkGate_KKK_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.KKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f3 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db 8a 04 16 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 30 04 0f c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db ?? c5 e5 69 d7 41 c5 e5 6a dc c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 ?? 89 c8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 81 f9 07 80 17 00 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}