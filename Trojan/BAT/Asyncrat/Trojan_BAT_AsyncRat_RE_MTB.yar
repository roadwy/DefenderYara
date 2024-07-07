
rule Trojan_BAT_AsyncRat_RE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 64 77 6f 73 5c 62 69 6e 5c 44 65 62 75 67 5c 44 6f 74 66 75 73 63 61 74 65 64 5c 77 69 6e 64 77 6f 73 2e 70 64 62 } //1 windwos\bin\Debug\Dotfuscated\windwos.pdb
		$a_01_1 = {24 36 34 64 37 38 61 38 33 2d 39 32 37 34 2d 34 63 64 38 2d 39 64 63 38 2d 65 35 66 37 36 66 30 39 62 61 33 37 } //1 $64d78a83-9274-4cd8-9dc8-e5f76f09ba37
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6c 00 69 00 6e 00 6b 00 70 00 69 00 63 00 74 00 75 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 71 00 2f 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 65 00 64 00 5f 00 31 00 30 00 31 00 2e 00 70 00 6e 00 67 00 } //1 https://www.linkpicture.com/q/converted_101.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}