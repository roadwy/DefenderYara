
rule Trojan_Win32_Upatre_GZY_MTB{
	meta:
		description = "Trojan:Win32/Upatre.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 00 5e 03 00 00 00 00 00 60 e8 90 01 04 5d 81 ed 10 00 00 00 81 ed 90 01 04 e9 90 01 04 6f 21 e3 0b b8 90 01 04 03 c5 81 c0 90 01 04 b9 90 01 04 ba 90 01 04 30 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}