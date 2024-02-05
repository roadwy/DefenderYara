
rule Trojan_Win32_Glupteba_DG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 08 81 c0 04 00 00 00 46 81 ee 92 99 08 f6 39 f8 75 } //02 00 
		$a_01_1 = {39 c0 74 01 ea 31 07 4e 29 f2 81 c7 04 00 00 00 29 ce 39 df 75 } //03 00 
		$a_03_2 = {83 c4 04 81 ef 01 00 00 00 21 fa 43 81 c2 90 02 04 81 fb 55 c2 00 01 75 90 00 } //03 00 
		$a_01_3 = {21 da 40 43 21 da 81 f8 0d c3 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}