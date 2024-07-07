
rule Trojan_Win32_Startpage_ACD_dll{
	meta:
		description = "Trojan:Win32/Startpage.ACD!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 37 37 39 64 68 2e 63 6f 6d 2f 3f } //1 .779dh.com/?
		$a_01_1 = {2e 76 32 35 38 2e 6e 65 74 2f 6c 69 73 74 2f 6c 69 73 74 } //1 .v258.net/list/list
		$a_01_2 = {2e 76 39 32 31 2e 63 6f 6d 2f 3f } //1 .v921.com/?
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 6a 73 } //1 rundll32.js
		$a_01_4 = {32 31 39 2e 31 34 31 2e 31 31 39 2e 31 30 30 3a 38 38 30 2f 3f } //1 219.141.119.100:880/?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}