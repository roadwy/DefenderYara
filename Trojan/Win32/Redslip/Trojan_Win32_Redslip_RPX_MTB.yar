
rule Trojan_Win32_Redslip_RPX_MTB{
	meta:
		description = "Trojan:Win32/Redslip.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 53 f8 39 13 8b 4d e4 0f 4f 13 8d 5b 28 03 53 d4 8d 41 ff 03 c2 33 d2 f7 f1 0f af c1 3b f8 0f 4d c7 8b f8 83 ee 01 75 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}