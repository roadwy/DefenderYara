
rule Trojan_Win32_MeduzaStealer_RA_MTB{
	meta:
		description = "Trojan:Win32/MeduzaStealer.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 08 a3 c9 06 06 c7 44 24 0c e6 6e 16 8c 8b 44 24 08 8b 4c 24 0c c7 44 24 08 dc a0 fb c8 } //5
		$a_01_1 = {4d 65 64 75 5a 5a 5a 61 } //1 MeduZZZa
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}