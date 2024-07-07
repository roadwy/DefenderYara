
rule Trojan_Win32_Glupteba_NA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d7 c1 ea 05 8d 90 02 06 89 90 02 06 8b 90 02 06 01 90 02 06 03 90 02 06 33 90 02 06 81 90 02 09 c7 05 90 02 08 90 18 31 90 02 03 81 90 02 09 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}