
rule Trojan_Win32_Cobaltstrike_SMLL_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.SMLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b d2 0a 8b c0 0f b6 08 83 e9 30 40 03 d1 80 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}