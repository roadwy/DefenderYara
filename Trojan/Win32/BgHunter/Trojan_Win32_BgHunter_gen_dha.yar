
rule Trojan_Win32_BgHunter_gen_dha{
	meta:
		description = "Trojan:Win32/BgHunter.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_43_0 = {43 44 13 c7 90 01 02 d6 bc 8e db c7 90 01 02 aa 9e 9f 12 c7 90 01 02 c5 ba db c1 c7 90 01 02 67 24 1f b0 c7 90 01 02 41 d5 a5 bb c7 90 01 02 7f 11 39 fe 90 00 05 } //00 1c 
		$a_0f_1 = {b6 04 32 8d 76 01 34 64 88 46 ff 0f b6 44 37 ff 34 64 88 86 33 04 00 00 83 e9 01 00 00 5d 04 00 00 88 01 05 80 5c 27 00 00 89 01 05 80 00 00 01 00 08 00 11 00 ac 21 53 68 61 64 6f 77 70 61 64 2e } //47 21 
	condition:
		any of ($a_*)
 
}