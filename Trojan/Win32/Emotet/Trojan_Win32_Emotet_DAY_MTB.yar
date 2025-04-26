
rule Trojan_Win32_Emotet_DAY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 8b 5c 24 ?? 55 8b 6c 24 ?? 56 8b 74 24 ?? 8b c1 33 d2 f7 f3 8a 44 55 00 8a 14 31 32 d0 88 14 31 41 3b cf 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}