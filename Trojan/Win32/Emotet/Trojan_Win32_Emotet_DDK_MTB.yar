
rule Trojan_Win32_Emotet_DDK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 50 e8 90 01 04 8a 44 24 20 8a 4c 24 14 8a d0 0a 44 24 14 f6 d2 f6 d1 0a d1 22 d0 8b 44 24 34 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}