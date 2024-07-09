
rule Trojan_Win32_Fosdimine_A{
	meta:
		description = "Trojan:Win32/Fosdimine.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 6d 69 6e 6e 65 72 73 } //1 execminners
		$a_01_1 = {2d 00 75 00 20 00 6a 00 6f 00 64 00 79 00 66 00 6f 00 73 00 74 00 65 00 72 00 } //1 -u jodyfoster
		$a_01_2 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 5c 00 61 00 75 00 74 00 6f 00 73 00 74 00 61 00 72 00 74 00 2e 00 76 00 62 00 70 00 } //1 bitcoin\autostart.vbp
		$a_01_3 = {6d 00 69 00 6e 00 65 00 72 00 5c 00 61 00 75 00 74 00 6f 00 73 00 74 00 61 00 72 00 74 00 2e 00 76 00 62 00 70 00 } //1 miner\autostart.vbp
		$a_03_4 = {63 6f 6e 66 69 67 6d 6f 64 [0-04] 64 65 74 65 63 74 6d 6f 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}