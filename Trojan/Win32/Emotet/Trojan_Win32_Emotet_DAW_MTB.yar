
rule Trojan_Win32_Emotet_DAW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 e1 c1 ea 90 01 01 8b c2 c1 e0 90 01 01 2b c2 03 c0 03 c0 8b d1 2b d0 8a 44 14 90 01 01 30 04 39 83 c1 01 81 f9 e0 07 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}