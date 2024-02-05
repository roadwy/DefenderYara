
rule Trojan_Win32_Azorult_NT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 8d 90 02 02 e8 90 02 04 30 90 01 01 81 90 02 05 90 18 43 3b dd 90 18 81 90 02 05 75 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}