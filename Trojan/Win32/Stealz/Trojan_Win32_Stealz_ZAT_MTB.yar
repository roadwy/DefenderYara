
rule Trojan_Win32_Stealz_ZAT_MTB{
	meta:
		description = "Trojan:Win32/Stealz.ZAT!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 00 6f 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 58 00 20 00 50 00 4f 00 53 00 54 00 } //1 do curl -X POST
		$a_00_1 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //1 bitcoin
		$a_00_2 = {63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 } //1 credential
		$a_00_3 = {62 00 61 00 63 00 6b 00 75 00 70 00 } //1 backup
		$a_00_4 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //1 screenshot
		$a_00_5 = {72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 } //1 recovery
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}