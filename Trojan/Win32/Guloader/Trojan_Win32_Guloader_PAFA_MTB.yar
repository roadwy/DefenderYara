
rule Trojan_Win32_Guloader_PAFA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.PAFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 61 6d 6d 65 72 6c 69 67 2e 6b 6c 65 } //1 jammerlig.kle
		$a_01_1 = {62 61 69 73 61 6b 68 5c 73 74 72 61 61 6c 69 6e 67 73 66 61 72 65 6e 73 } //1 baisakh\straalingsfarens
		$a_01_2 = {62 00 72 00 6f 00 6e 00 6b 00 69 00 65 00 72 00 6e 00 65 00 73 00 20 00 69 00 6e 00 73 00 70 00 65 00 6b 00 74 00 72 00 73 00 } //1 bronkiernes inspektrs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}