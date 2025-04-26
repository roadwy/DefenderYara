
rule Trojan_MacOS_OpinionSpy_G_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 6f 73 74 2e 73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d 2f 70 61 63 6b 61 67 65 73 2f } //2 post.securestudies.com/packages/
		$a_00_1 = {2f 4d 43 6f 6e 74 65 6e 74 49 33 2e 67 7a } //1 /MContentI3.gz
		$a_00_2 = {5a 58 54 5f 4d 41 43 2f 42 75 6e 64 6c 65 73 2f 44 6f 77 6e 6c 6f 61 64 } //1 ZXT_MAC/Bundles/Download
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}