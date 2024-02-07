
rule Trojan_Win32_Banker_AF{
	meta:
		description = "Trojan:Win32/Banker.AF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {bf 01 00 00 00 8b 45 f0 0f b7 5c 78 fe 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03 } //01 00 
		$a_01_1 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 73 00 65 00 74 00 20 00 6f 00 70 00 6d 00 6f 00 64 00 65 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 } //01 00  netsh firewall set opmode enable
		$a_01_2 = {31 00 32 00 31 00 41 00 45 00 39 00 33 00 33 00 43 00 36 00 35 00 44 00 41 00 33 00 42 00 30 00 37 00 37 00 38 00 31 00 38 00 37 00 } //00 00  121AE933C65DA3B0778187
	condition:
		any of ($a_*)
 
}