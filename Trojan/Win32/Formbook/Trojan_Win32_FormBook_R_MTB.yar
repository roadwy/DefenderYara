
rule Trojan_Win32_FormBook_R_MTB{
	meta:
		description = "Trojan:Win32/FormBook.R!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 f1 43 e2 db ec } //01 00 
		$a_01_1 = {89 0c 18 39 } //02 00 
		$a_01_2 = {81 f1 d8 79 24 d6 } //00 00 
	condition:
		any of ($a_*)
 
}