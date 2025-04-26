
rule Trojan_Win32_Kelios_GDX_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f c0 e0 f6 d8 32 cb c1 e8 ?? fe c9 f6 d1 0f b6 d0 80 e9 ?? 80 f1 ?? c1 f8 ?? 89 44 54 ?? 32 d9 58 52 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}