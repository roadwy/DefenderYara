
rule Trojan_Win32_MarsStealer_RDA_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 0f b6 14 37 c1 e2 08 8b 0c b0 46 0f b6 01 32 9c 10 00 7a 42 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}