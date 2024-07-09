
rule Trojan_Win32_Glupteba_NE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 a4 24 e8 00 00 00 8b 84 24 e8 00 00 00 81 [0-0a] 8b 84 [0-05] 8a 94 06 [0-04] 88 14 01 5e 81 c4 [0-04] c2 } //1
		$a_02_1 = {46 81 fe a9 10 00 00 7c ea 90 09 0d 00 81 fe [0-04] 75 05 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}