
rule Trojan_WinNT_Regin_gen_A{
	meta:
		description = "Trojan:WinNT/Regin.gen.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 75 10 8b 46 64 c1 e8 02 50 ff 75 0c e8 } //01 00 
		$a_01_1 = {05 00 00 84 c0 75 0e ff 75 10 8b 45 0c 53 ff 30 e8 } //01 00 
		$a_01_2 = {8b 45 fc 8b 40 28 03 45 08 53 ff 75 08 ff d0 8b d8 f7 db 1a db fe c3 } //00 00 
	condition:
		any of ($a_*)
 
}