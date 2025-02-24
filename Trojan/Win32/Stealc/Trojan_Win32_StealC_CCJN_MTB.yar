
rule Trojan_Win32_StealC_CCJN_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 c1 e0 04 03 45 e8 8d 0c 33 33 c1 33 45 fc 89 45 d8 8b 45 d8 29 45 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}