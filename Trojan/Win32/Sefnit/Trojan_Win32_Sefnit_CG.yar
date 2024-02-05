
rule Trojan_Win32_Sefnit_CG{
	meta:
		description = "Trojan:Win32/Sefnit.CG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 fe 10 7c d6 6a 01 e8 90 01 04 59 33 f6 e8 90 01 04 6a 63 99 59 f7 f9 90 00 } //01 00 
		$a_03_1 = {6a 40 6a 22 bf 90 01 04 57 8d 8d 78 fe ff ff e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}