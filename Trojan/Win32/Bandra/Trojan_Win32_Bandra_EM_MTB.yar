
rule Trojan_Win32_Bandra_EM_MTB{
	meta:
		description = "Trojan:Win32/Bandra.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {83 e0 03 8a 80 90 01 04 30 81 90 01 04 41 81 f9 7e 07 00 00 72 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}