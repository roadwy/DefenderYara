
rule Trojan_Win32_Emotet_DBL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f6 33 c0 8b f2 8a 54 34 90 01 11 81 e2 ff 00 00 00 bb 90 01 04 03 c2 99 f7 fb 8a 1f 8a 44 14 90 01 01 32 d8 88 1f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}