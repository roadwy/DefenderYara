
rule Trojan_Win32_Copak_CD_MTB{
	meta:
		description = "Trojan:Win32/Copak.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 13 01 ff 43 47 21 ff 39 f3 75 de } //02 00 
		$a_03_1 = {31 08 81 ef 90 02 04 81 ef 90 02 04 81 c0 01 00 00 00 09 d7 39 f0 75 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}