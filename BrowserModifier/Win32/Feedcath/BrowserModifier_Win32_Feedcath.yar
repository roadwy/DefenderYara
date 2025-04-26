
rule BrowserModifier_Win32_Feedcath{
	meta:
		description = "BrowserModifier:Win32/Feedcath,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 70 00 70 00 72 00 6f 00 76 00 65 00 64 00 20 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 } //1 \Internet Explorer\Approved Extensions
		$a_01_1 = {2f 66 77 6c 69 6e 6b 2f 3f 4c 69 6e 6b 49 64 3d 31 35 39 36 35 31 } //1 /fwlink/?LinkId=159651
		$a_01_2 = {67 00 65 00 74 00 6d 00 70 00 6f 00 66 00 66 00 65 00 72 00 00 00 } //10
		$a_01_3 = {67 00 65 00 74 00 66 00 6f 00 6f 00 66 00 66 00 65 00 72 00 00 00 } //10
		$a_01_4 = {5c 74 68 65 6e 74 2d 74 65 61 6d 5c 69 65 5c 42 69 6e 61 72 69 65 73 5c 43 6f 6e 74 65 6e 74 } //10 \thent-team\ie\Binaries\Content
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=32
 
}