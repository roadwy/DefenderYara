
rule Trojan_Win32_Glupteba_FQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 d8 85 40 00 58 09 fe 81 ef 90 01 04 e8 90 01 04 01 f6 46 31 01 29 f7 47 41 39 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}