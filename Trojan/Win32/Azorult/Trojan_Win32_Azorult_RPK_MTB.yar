
rule Trojan_Win32_Azorult_RPK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 d1 fe c1 32 c8 02 c8 f6 d1 02 c8 80 f1 c1 02 c8 fe c9 80 f1 d7 fe c9 88 88 } //00 00 
	condition:
		any of ($a_*)
 
}