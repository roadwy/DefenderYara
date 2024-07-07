
rule TrojanDownloader_Win32_Renos_LU{
	meta:
		description = "TrojanDownloader:Win32/Renos.LU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 44 69 72 00 } //1 牐杯慲䙭汩獥楄r
		$a_01_1 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 00 } //1
		$a_01_2 = {44 61 46 75 64 67 65 00 } //1 慄畆杤e
		$a_01_3 = {73 65 74 75 70 2d 32 2e 31 31 2d 65 6e 67 2e 65 78 65 00 } //1
		$a_01_4 = {75 70 64 61 74 65 2d 32 2e 31 31 2d 65 6e 67 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}