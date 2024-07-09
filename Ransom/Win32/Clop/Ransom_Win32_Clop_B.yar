
rule Ransom_Win32_Clop_B{
	meta:
		description = "Ransom:Win32/Clop.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {73 56 8b 55 cc 8b 45 dc 8b 0c 90 90 89 4d 94 8b 15 ?? ?? ?? ?? 89 55 98 8b 45 94 2b 45 cc 89 45 94 8b 4d e4 83 e9 ?? 89 4d e4 8b 55 94 33 55 98 89 55 94 8b 45 e4 2d ?? ?? ?? ?? 89 45 e4 c1 45 94 07 8b 4d 94 33 4d 98 89 4d 94 8b 55 cc 8b 45 f8 8b 4d 94 89 0c 90 90 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}