
rule Trojan_Win32_Redline_CCCU_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d8 33 de 33 f6 8b c6 33 d8 33 db 8b f0 8b f3 8b c6 f6 2f 47 e2 } //00 00 
	condition:
		any of ($a_*)
 
}