
rule Trojan_Win32_Razy_CR_MTB{
	meta:
		description = "Trojan:Win32/Razy.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 30 29 d1 81 c0 04 00 00 00 39 d8 75 ed } //02 00 
		$a_01_1 = {31 16 46 09 df 09 db 39 c6 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}