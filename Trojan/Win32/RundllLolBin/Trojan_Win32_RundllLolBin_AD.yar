
rule Trojan_Win32_RundllLolBin_AD{
	meta:
		description = "Trojan:Win32/RundllLolBin.AD,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  rundll32.exe
		$a_00_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 } //01 00  javascript
		$a_00_2 = {52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  RunHTMLApplication
		$a_00_3 = {73 00 63 00 72 00 69 00 70 00 74 00 3a 00 68 00 74 00 74 00 70 00 } //00 00  script:http
	condition:
		any of ($a_*)
 
}