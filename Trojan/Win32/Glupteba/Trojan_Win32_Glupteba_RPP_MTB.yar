
rule Trojan_Win32_Glupteba_RPP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 f6 74 01 ea 31 07 90 02 10 81 c7 04 00 00 00 39 cf 75 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}