
rule Trojan_Win32_Glupteba_PE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ce c1 e1 04 03 90 02 06 8b 90 01 01 c1 90 02 02 89 90 02 03 89 90 02 03 8b 90 02 06 01 90 02 03 8b 90 02 03 8d 90 02 02 33 90 01 01 31 90 02 03 83 90 02 06 c7 90 02 09 89 90 02 03 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}