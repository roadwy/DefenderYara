
rule Trojan_Win32_Angod{
	meta:
		description = "Trojan:Win32/Angod,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 64 6f 6e 67 61 2e 63 6e 2f 63 6f 75 6e 74 2f 64 61 74 61 } //02 00  adonga.cn/count/data
		$a_02_1 = {66 69 6c 65 6e 61 6d 65 3d 90 02 06 6f 70 65 6e 90 00 } //01 00 
		$a_00_2 = {67 65 74 73 65 72 76 62 79 6e 61 6d 65 } //01 00  getservbyname
		$a_00_3 = {67 65 74 68 6f 73 74 6e 61 6d 65 } //01 00  gethostname
		$a_00_4 = {67 65 74 70 72 6f 74 6f 62 79 6e 61 6d 65 } //00 00  getprotobyname
	condition:
		any of ($a_*)
 
}