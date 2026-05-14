
rule Trojan_Win32_Jaik_MK_MTB{
	meta:
		description = "Trojan:Win32/Jaik.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d1 ea 83 e0 01 f7 d8 25 20 83 b8 ed 33 d0 83 ee 01 ?? ?? 89 14 8d e0 db 14 00 41 81 f9 00 01 00 00 ?? ?? 5e ba 00 04 00 00 8b 8a e0 d7 14 00 0f b6 c1 c1 e9 08 33 0c 85 e0 db 14 00 89 8a e0 db 14 } //25
	condition:
		((#a_03_0  & 1)*25) >=25
 
}