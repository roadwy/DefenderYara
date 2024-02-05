
rule Trojan_Win32_Kadena_gen_D{
	meta:
		description = "Trojan:Win32/Kadena.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {37 48 45 76 90 01 01 74 47 73 74 90 01 01 72 72 6f 72 90 00 } //00 00 
		$a_00_1 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}