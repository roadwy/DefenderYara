
rule Trojan_Win32_Copak_CH_MTB{
	meta:
		description = "Trojan:Win32/Copak.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 37 89 c3 47 01 db b8 90 02 04 39 d7 75 e6 90 00 } //02 00 
		$a_01_1 = {21 df 31 0e 43 09 df 46 4f 29 db 39 d6 75 d9 } //00 00 
	condition:
		any of ($a_*)
 
}