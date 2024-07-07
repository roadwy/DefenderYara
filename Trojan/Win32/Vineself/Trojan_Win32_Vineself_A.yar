
rule Trojan_Win32_Vineself_A{
	meta:
		description = "Trojan:Win32/Vineself.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 f2 90 01 01 88 11 41 4e 75 90 00 } //5
		$a_00_1 = {63 00 3a 00 5c 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 5c 00 77 00 69 00 6e 00 66 00 6f 00 6e 00 74 00 33 00 32 00 2e 00 63 00 70 00 6c 00 } //1 c:\\windows\\temp\\winfont32.cpl
		$a_00_2 = {25 63 25 64 2f 25 63 25 64 25 63 25 64 25 63 25 64 2f 25 63 25 64 25 63 25 64 25 63 25 64 2f } //1 %c%d/%c%d%c%d%c%d/%c%d%c%d%c%d/
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=7
 
}