
rule Trojan_Win32_Stealerc_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 30 03 0a 55 54 c7 44 24 34 48 02 0a 0a 8a 44 0c 2c 34 ?? 88 84 0c fc 00 00 00 41 83 f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}