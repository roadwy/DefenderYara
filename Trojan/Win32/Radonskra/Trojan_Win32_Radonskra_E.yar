
rule Trojan_Win32_Radonskra_E{
	meta:
		description = "Trojan:Win32/Radonskra.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 7d fc 20 76 ?? 80 7d fc 2c 75 ?? e9 8c 00 00 00 80 7d fc 7d 75 } //1
		$a_10_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_2 = {22 73 61 66 65 62 72 6f 77 73 69 6e 67 22 3a 7b 22 65 6e 61 62 6c 65 64 22 3a 66 61 6c 73 65 7d 2c } //1 "safebrowsing":{"enabled":false},
		$a_01_3 = {53 79 73 74 65 6d 53 63 72 69 70 74 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 祓瑳浥捓楲瑰匀䙏坔剁居楍牣獯景屴楗摮睯屳畃牲湥噴牥楳湯剜湵
	condition:
		((#a_03_0  & 1)*1+(#a_10_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}