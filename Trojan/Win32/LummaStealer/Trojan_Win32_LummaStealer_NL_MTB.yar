
rule Trojan_Win32_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 02 8b e9 33 c0 33 ff 3b eb 74 2e } //3
		$a_03_1 = {e8 36 fa ff ff 83 c4 ?? 80 7e 48 00 75 10 85 c0 78 0c 8b 4c 24 14 88 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win32_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {7c 16 43 33 f6 8b 47 ?? 8b d6 e8 e3 08 fc ff e8 26 fd fa ff 46 4b 75 ed } //5
		$a_01_1 = {44 69 65 64 48 69 73 74 6f 72 69 63 } //1 DiedHistoric
		$a_01_2 = {41 6e 64 72 65 77 73 20 53 69 67 6e 65 64 20 53 79 6d 70 6f 73 69 75 6d 20 43 61 72 74 20 4e 61 74 69 6f 6e 20 45 75 72 6f 73 } //1 Andrews Signed Symposium Cart Nation Euros
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}