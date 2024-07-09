
rule Trojan_Win32_Konirat_B{
	meta:
		description = "Trojan:Win32/Konirat.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 55 73 65 72 73 5c 7a 65 75 73 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 76 69 72 75 73 2d 64 6c 6c 5c [0-20] 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}