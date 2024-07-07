
rule Trojan_Win32_MortyStealer_MA_MTB{
	meta:
		description = "Trojan:Win32/MortyStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 66 89 44 24 16 8b 41 08 89 44 24 18 8b 41 0c 8b 4c 24 34 89 44 24 1c 0f b6 c1 66 c1 e0 08 66 89 44 24 20 8b c1 c1 e8 08 0f b6 c0 66 c1 e0 08 66 89 44 24 22 c1 e9 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}