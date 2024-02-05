
rule Trojan_Win32_RedLine_B_MTB{
	meta:
		description = "Trojan:Win32/RedLine.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 db f6 17 80 37 56 47 e2 f6 } //01 00 
		$a_01_1 = {f6 17 33 db 80 07 44 80 2f 86 f6 2f 47 e2 f1 } //00 00 
	condition:
		any of ($a_*)
 
}