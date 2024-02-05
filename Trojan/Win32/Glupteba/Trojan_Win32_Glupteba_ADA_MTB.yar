
rule Trojan_Win32_Glupteba_ADA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_80_0 = {31 0e 81 ea 01 00 00 00 81 c6 04 00 00 00 39 c6 75 e9 } //1��  0a 00 
		$a_80_1 = {8b 34 24 83 c4 04 81 ef 7c ad cf d2 81 ea ce 1e 34 72 58 89 d3 } //�4$����|��ҁ��4rX��  00 00 
	condition:
		any of ($a_*)
 
}