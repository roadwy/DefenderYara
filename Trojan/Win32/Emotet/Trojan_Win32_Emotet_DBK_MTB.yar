
rule Trojan_Win32_Emotet_DBK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d3 8b c6 33 d2 f7 74 24 90 01 01 8b 44 24 90 01 01 8a 0c 50 8a 14 3e 32 d1 88 14 3e 46 3b f5 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}