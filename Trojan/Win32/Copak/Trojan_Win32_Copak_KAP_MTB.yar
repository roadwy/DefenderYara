
rule Trojan_Win32_Copak_KAP_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 01 01 d3 01 de 81 e0 90 01 04 f7 d3 81 ee 90 01 04 be 90 01 04 31 07 21 d2 21 db 47 4b 4b 4e 41 01 f6 4a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}