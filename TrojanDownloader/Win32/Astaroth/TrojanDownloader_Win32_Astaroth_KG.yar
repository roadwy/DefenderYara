
rule TrojanDownloader_Win32_Astaroth_KG{
	meta:
		description = "TrojanDownloader:Win32/Astaroth.KG,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 00 63 00 68 00 6f 00 20 00 } //1 echo 
		$a_00_1 = {5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 } //1 \programdata\
		$a_02_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-04] 2f 00 72 00 65 00 73 00 65 00 74 00 [0-10] 65 00 78 00 69 00 74 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}