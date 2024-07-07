
rule Trojan_Win32_StealC_CCID_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 8d 4d 90 01 01 8b 55 90 01 01 33 45 90 01 01 33 d0 89 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}