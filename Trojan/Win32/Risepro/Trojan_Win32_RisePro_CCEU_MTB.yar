
rule Trojan_Win32_RisePro_CCEU_MTB{
	meta:
		description = "Trojan:Win32/RisePro.CCEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8b 4d fc 89 85 90 01 01 fe ff ff 8d 90 02 05 89 8d 90 01 01 fe ff ff c5 fe 6f 85 90 01 01 fe ff ff c5 fd ef 90 02 05 50 c5 fd 7f 90 02 05 57 c5 f8 77 ff d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}