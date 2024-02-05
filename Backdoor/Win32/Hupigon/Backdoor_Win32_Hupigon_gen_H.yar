
rule Backdoor_Win32_Hupigon_gen_H{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {10 e9 86 00 00 00 8b 55 fc b8 90 01 04 e8 90 01 04 85 c0 74 14 8d 45 fc e8 90 01 04 ba 90 01 04 8b c6 e8 90 01 04 8b 55 fc b8 90 01 04 e8 90 01 04 85 c0 74 3c 8b 45 fc e8 90 00 } //01 00 
		$a_01_1 = {cf b5 cd b3 b2 bb c4 dc ca b9 d3 c3 20 54 65 6c } //02 00 
		$a_03_2 = {48 00 8b 00 8b 15 90 01 02 47 00 e8 90 01 02 fc ff a1 90 01 02 48 00 8b 00 90 09 09 00 8b 0d 90 01 02 48 00 a1 90 01 18 90 03 0c 00 c6 40 5b 00 a1 90 01 02 48 00 8b 00 e8 90 01 02 fc ff c3 90 02 02 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 90 01 02 48 00 c7 40 04 07 00 00 00 eb 51 90 00 } //02 00 
		$a_03_3 = {49 00 b1 fe ba 90 01 01 00 00 00 e8 90 01 03 ff a1 90 01 02 48 00 8b 00 e8 90 01 02 fc ff c3 55 8b ec 8b 45 08 48 74 24 48 74 05 48 74 10 eb 5f a1 90 01 02 48 00 c7 40 04 07 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}