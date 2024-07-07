
rule Trojan_Win32_Emotet_DAX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 e1 d1 ea 6b d2 90 01 01 8b c1 2b c2 8a 54 04 90 01 01 30 14 39 83 c1 01 81 f9 e0 07 00 00 75 90 00 } //1
		$a_02_1 = {f7 e1 c1 ea 90 01 01 6b d2 90 01 01 8b c1 2b c2 8a 14 18 30 14 31 83 c1 01 3b cf 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}