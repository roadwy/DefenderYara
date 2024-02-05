
rule Trojan_Win32_Razy_CC_MTB{
	meta:
		description = "Trojan:Win32/Razy.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 0e 29 f8 81 c6 04 00 00 00 29 c0 81 e8 92 2f 63 8b 39 de 75 e5 } //00 00 
	condition:
		any of ($a_*)
 
}