
rule Trojan_Win32_Predator_RPW_MTB{
	meta:
		description = "Trojan:Win32/Predator.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 45 66 89 45 a2 58 6a 55 66 89 45 b0 58 6a 69 66 89 45 b2 58 6a 56 66 89 45 b4 58 6a 6e 66 89 45 b6 58 66 89 45 b8 6a 42 58 66 89 45 ba 6a 71 58 66 89 45 bc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}