
rule Trojan_PowerShell_LummaStealer_AC_MTB{
	meta:
		description = "Trojan:PowerShell/LummaStealer.AC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 00 53 00 74 00 72 00 69 00 6e 00 67 00 5d 00 27 00 27 00 2e 00 43 00 68 00 61 00 72 00 73 00 } //1 [String]''.Chars
		$a_00_1 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 5d 00 3a 00 3a 00 4e 00 65 00 77 00 28 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 } //1 [System.Net.WebClient]::New().DownloadString('http
		$a_00_2 = {2d 00 4a 00 6f 00 69 00 6e 00 } //1 -Join
		$a_00_3 = {2e 00 78 00 6c 00 6c 00 } //1 .xll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}