
rule Trojan_Win32_Tracur_AQ{
	meta:
		description = "Trojan:Win32/Tracur.AQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {28 2f 5c 2e 62 69 6e 67 5c 2e 5b 61 2d 7a 5d 7b 32 2c 34 7d } //2 (/\.bing\.[a-z]{2,4}
		$a_01_1 = {22 6d 61 74 63 68 65 73 22 3a 20 5b 20 22 68 74 74 70 3a 2f 2f 2a 2f 2a 22 2c 20 22 68 74 74 70 73 3a 2f 2f 2a 2f 2a 22 20 5d 2c } //2 "matches": [ "http://*/*", "https://*/*" ],
		$a_01_2 = {54 46 61 6b 65 52 65 66 65 72 72 65 72 } //2 TFakeReferrer
		$a_00_3 = {2f 6c 6f 67 69 6e 2f 20 2f 74 77 65 65 74 2f 20 61 63 74 69 6f 6e 3d 65 6d 62 65 64 2d 66 6c 61 73 68 } //2 /login/ /tweet/ action=embed-flash
		$a_01_4 = {61 64 75 72 6c 3d } //1 adurl=
		$a_00_5 = {4d 61 73 74 65 72 43 61 72 64 } //1 MasterCard
		$a_00_6 = {70 6f 72 6e } //1 porn
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}