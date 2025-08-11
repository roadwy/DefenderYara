
rule Trojan_BAT_Amadey_MCF_MTB{
	meta:
		description = "Trojan:BAT/Amadey.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 32 65 63 2d 32 36 39 35 66 64 66 30 38 38 38 65 } //1 a2ec-2695fdf0888e
		$a_01_1 = {6b 6f 69 00 44 6f 77 6e 6c 6f } //1 潫i潄湷潬
		$a_01_2 = {57 94 02 28 49 03 00 00 00 fa 25 33 00 16 00 00 01 } //1
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e 61 6d 32 2e 62 69 6e } //1 DownloaderApp.am2.bin
		$a_01_4 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //1 LzmaDecoder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}