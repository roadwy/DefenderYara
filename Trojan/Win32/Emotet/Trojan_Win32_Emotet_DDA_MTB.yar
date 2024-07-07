
rule Trojan_Win32_Emotet_DDA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 11 89 15 90 01 04 a1 90 01 04 2d 59 11 00 00 a3 90 01 04 8b 15 90 01 04 8b c0 81 c2 59 11 00 00 8b c0 a1 90 01 04 8b c0 8b ca 8b c0 a3 90 01 04 8b c0 31 0d 90 01 04 a1 90 01 04 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}