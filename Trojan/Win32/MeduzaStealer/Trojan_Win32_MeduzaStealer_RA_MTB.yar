
rule Trojan_Win32_MeduzaStealer_RA_MTB{
	meta:
		description = "Trojan:Win32/MeduzaStealer.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {c7 44 24 08 a3 c9 06 06 c7 44 24 0c e6 6e 16 8c 8b 44 24 08 8b 4c 24 0c c7 44 24 08 dc a0 fb c8 } //01 00 
		$a_01_1 = {4d 65 64 75 5a 5a 5a 61 } //00 00  MeduZZZa
	condition:
		any of ($a_*)
 
}