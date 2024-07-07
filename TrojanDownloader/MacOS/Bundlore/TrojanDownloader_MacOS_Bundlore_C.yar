
rule TrojanDownloader_MacOS_Bundlore_C{
	meta:
		description = "TrojanDownloader:MacOS/Bundlore.C,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00 78 00 20 00 2f 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 2f 00 } //2 chmod +x /private/
		$a_00_1 = {63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00 78 00 20 00 2f 00 76 00 61 00 72 00 2f 00 } //2 chmod +x /var/
		$a_00_2 = {2f 00 6d 00 6d 00 2d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 6d 00 61 00 63 00 6f 00 73 00 2e 00 61 00 70 00 70 00 2f 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 6d 00 61 00 63 00 6f 00 73 00 2f 00 6d 00 6d 00 2d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 6d 00 61 00 63 00 6f 00 73 00 } //3 /mm-install-macos.app/contents/macos/mm-install-macos
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*3) >=5
 
}