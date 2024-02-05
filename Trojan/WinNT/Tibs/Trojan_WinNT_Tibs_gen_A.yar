
rule Trojan_WinNT_Tibs_gen_A{
	meta:
		description = "Trojan:WinNT/Tibs.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 3a 6e 64 69 73 74 08 81 3a 4e 44 49 53 75 07 e8 0c 00 00 00 eb 05 e8 90 01 02 ff ff ab eb c8 5e c3 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}