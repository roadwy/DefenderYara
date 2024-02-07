
rule Trojan_Win32_CookieStealer_MSR{
	meta:
		description = "Trojan:Win32/CookieStealer!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 66 61 73 74 65 72 70 64 66 69 6e 73 74 61 6c 6c 2e 78 79 7a 3a 31 30 30 30 30 2f 63 6f 6f 6b 69 65 } //01 00  http://fasterpdfinstall.xyz:10000/cookie
		$a_01_1 = {6f 70 65 6e 20 63 68 72 6f 6d 27 73 20 63 6f 6f 6b 69 65 20 66 69 6c 65 } //01 00  open chrom's cookie file
		$a_01_2 = {6f 70 65 6e 20 66 69 72 65 66 6f 78 27 73 20 63 6f 6f 6b 69 65 20 66 69 6c 65 20 } //01 00  open firefox's cookie file 
		$a_01_3 = {69 6e 73 74 61 67 72 61 6d 20 63 6f 6f 6b 69 65 } //01 00  instagram cookie
		$a_01_4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //01 00  Microsoft\Windows\Cookies
		$a_01_5 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 } //01 00  SELECT * FROM cookies
		$a_01_6 = {43 48 43 6f 6f 6b 69 65 2e 70 64 62 } //00 00  CHCookie.pdb
	condition:
		any of ($a_*)
 
}