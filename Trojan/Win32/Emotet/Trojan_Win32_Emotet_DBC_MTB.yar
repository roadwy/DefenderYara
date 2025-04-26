
rule Trojan_Win32_Emotet_DBC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 8b 5c 24 ?? 55 8b 6c 24 ?? 56 8b 74 24 ?? 8d [0-05] 33 d2 8b c1 f7 f3 8a 44 55 00 30 04 31 41 3b cf 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}