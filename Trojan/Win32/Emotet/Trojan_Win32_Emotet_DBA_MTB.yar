
rule Trojan_Win32_Emotet_DBA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 33 d2 8d 0c 06 8b c6 f7 75 ?? 8b 45 ?? 8a 04 50 30 01 46 3b 75 10 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}