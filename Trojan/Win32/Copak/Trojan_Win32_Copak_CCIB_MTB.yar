
rule Trojan_Win32_Copak_CCIB_MTB{
	meta:
		description = "Trojan:Win32/Copak.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {29 db 09 d2 e8 90 01 04 31 38 4b 40 29 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}