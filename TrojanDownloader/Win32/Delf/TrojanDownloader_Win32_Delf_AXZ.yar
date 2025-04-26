
rule TrojanDownloader_Win32_Delf_AXZ{
	meta:
		description = "TrojanDownloader:Win32/Delf.AXZ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {35 38 2e 32 32 31 2e 33 31 2e 32 32 3a 38 30 32 2f 66 74 64 61 74 61 2f } //1 58.221.31.22:802/ftdata/
		$a_01_1 = {00 64 6e 66 2e 65 78 65 } //1 搀普攮數
		$a_01_2 = {00 5c 6e 76 62 61 63 6b 75 70 2e 64 6c 6c } //1 尀癮慢正灵搮汬
		$a_01_3 = {5c 57 69 6e 53 6f 63 6b 32 5c 50 61 72 61 6d 65 74 65 72 73 5c 50 72 6f 74 6f 63 6f 6c 5f 43 61 74 61 6c 6f 67 39 5c 43 61 74 61 6c 6f 67 5f 45 6e 74 72 69 65 73 5c } //1 \WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}