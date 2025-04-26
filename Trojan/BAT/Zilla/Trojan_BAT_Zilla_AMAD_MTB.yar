
rule Trojan_BAT_Zilla_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 09 91 07 09 07 8e 69 5d 91 61 28 ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 09 17 58 0d 09 06 8e 69 32 d6 } //4
		$a_80_1 = {35 77 67 45 50 56 6b 48 39 48 34 3d } //5wgEPVkH9H4=  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}