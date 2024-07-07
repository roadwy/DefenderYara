
rule Trojan_Win32_LethicStealer_RPN_MTB{
	meta:
		description = "Trojan:Win32/LethicStealer.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0a 88 dd d2 e5 00 e9 88 08 0f b6 4d fc 89 d8 d3 f8 0f b6 4d fc 29 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}