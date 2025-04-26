
rule Trojan_Win32_Emotet_DFL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e6 c1 ea 05 6b d2 2e 8b c6 2b c2 8a 14 41 30 14 1e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}