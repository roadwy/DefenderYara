
rule Trojan_Win32_Glupteba_PR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b e5 5d c2 08 00 90 09 3e 00 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 2b 90 02 02 89 90 02 02 8b 90 02 02 51 8d 90 02 02 52 e8 90 02 04 e9 90 02 04 8b 90 02 02 8b 90 02 02 89 90 02 01 8b 90 02 02 8b 90 02 02 89 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}