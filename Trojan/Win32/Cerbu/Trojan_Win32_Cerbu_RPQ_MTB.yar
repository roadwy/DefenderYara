
rule Trojan_Win32_Cerbu_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 75 e4 8b 45 d8 03 34 90 03 75 fc 8b 4d ec 8b 11 2b d6 8b 45 ec 89 10 8b 4d f4 8b 55 ec 8b 02 89 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}