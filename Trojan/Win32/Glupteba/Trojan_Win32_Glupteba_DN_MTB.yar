
rule Trojan_Win32_Glupteba_DN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 de 29 f3 e8 90 02 04 09 db 31 17 bb da a8 70 80 81 eb 58 7a ec e7 81 c7 01 00 00 00 39 c7 75 90 00 } //02 00 
		$a_01_1 = {59 56 5b 81 c3 01 00 00 00 29 f6 81 c2 01 00 00 00 81 c3 01 00 00 00 81 fa 78 ee 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}