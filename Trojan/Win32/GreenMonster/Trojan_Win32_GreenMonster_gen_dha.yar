
rule Trojan_Win32_GreenMonster_gen_dha{
	meta:
		description = "Trojan:Win32/GreenMonster.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_43_0 = {83 b4 45 90 01 05 40 83 f8 40 72 f1 90 00 05 } //00 18 
		$a_50_1 = {00 6a 00 6a 00 6a 00 6a 00 6a 00 8d 85 90 01 04 50 6a 00 ff 90 00 00 00 5d 04 00 00 85 01 05 80 5c 27 00 00 86 01 05 80 00 00 01 00 08 00 11 00 ac 21 50 61 6e 50 61 6c 73 2e 67 65 6e 21 64 68 61 00 00 } //02 40 
	condition:
		any of ($a_*)
 
}