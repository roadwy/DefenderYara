
rule Trojan_WinNT_Umveet_gen_A{
	meta:
		description = "Trojan:WinNT/Umveet.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 08 7c e0 68 9d 8f a0 c3 56 90 09 07 00 47 81 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}