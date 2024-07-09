
rule Trojan_Win32_Webprefix_B{
	meta:
		description = "Trojan:Win32/Webprefix.B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 76 70 6c 61 79 63 68 65 63 6b 2e 63 6f 6d 2f 67 6f 2f } //1 .vplaycheck.com/go/
		$a_00_1 = {76 70 6c 61 79 2d 74 6f 2e 63 6f 6d } //1 vplay-to.com
		$a_00_2 = {53 6f 66 74 77 61 72 65 61 6b 74 75 61 6c 69 73 69 65 72 75 6e 67 7c 68 74 74 70 3a } //1 Softwareaktualisierung|http:
		$a_00_3 = {26 76 3d 25 64 2e 25 64 2e 25 64 00 } //10
		$a_03_4 = {80 38 3b 75 02 88 18 41 3b ce 72 ed 57 8d 85 ?? ?? ff ff 50 6a 07 53 ff 75 10 ff 75 ?? ff 15 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10+(#a_03_4  & 1)*10) >=21
 
}