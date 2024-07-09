
rule Trojan_Win32_PsDownload_GBX_MTB{
	meta:
		description = "Trojan:Win32/PsDownload.GBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c1 66 89 85 c2 fb ff ff 33 c0 5f 66 89 85 c4 fb ff ff 5e 0f 1f 44 00 00 66 31 8c 45 32 fb ff ff 40 83 f8 49 73 09 66 8b 8d 30 fb ff ff eb } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}