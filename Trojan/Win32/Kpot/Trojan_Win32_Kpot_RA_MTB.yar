
rule Trojan_Win32_Kpot_RA_MTB{
	meta:
		description = "Trojan:Win32/Kpot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 6c 24 ?? 52 ef 6f 62 2d ?? ?? ?? ?? 81 6c 24 ?? 68 19 2a 14 81 44 24 ?? be 08 9a 76 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}