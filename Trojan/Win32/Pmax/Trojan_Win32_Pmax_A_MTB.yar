
rule Trojan_Win32_Pmax_A_MTB{
	meta:
		description = "Trojan:Win32/Pmax.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8c 24 b0 00 00 00 68 19 00 02 00 89 8c 24 34 02 00 00 c5 f8 28 8c 24 28 02 00 00 c5 f0 57 8c 24 18 01 00 00 6a 00 50 c5 f8 29 8c 24 20 01 00 00 68 01 00 00 80 c5 f8 77 ff d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}