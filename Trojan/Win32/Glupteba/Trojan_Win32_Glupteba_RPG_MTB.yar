
rule Trojan_Win32_Glupteba_RPG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 f6 31 17 81 ee 90 01 04 29 c0 47 39 df 90 02 10 8d 14 0a 8b 12 81 e2 90 01 04 81 c1 90 01 04 81 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}