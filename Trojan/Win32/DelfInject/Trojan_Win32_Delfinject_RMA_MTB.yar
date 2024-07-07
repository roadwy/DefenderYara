
rule Trojan_Win32_Delfinject_RMA_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 ee 0b 00 00 8d 04 08 50 58 6a 04 68 00 10 00 00 a1 90 01 04 50 8b 06 8d 04 80 8b 15 90 01 04 8b 44 c2 90 01 01 03 05 90 01 04 50 e8 90 01 04 a3 90 01 04 8d 8b 90 01 04 05 ee 0b 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}