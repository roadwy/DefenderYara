
rule TrojanDownloader_Win32_Scar_C{
	meta:
		description = "TrojanDownloader:Win32/Scar.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 52 75 6e 5c 33 36 30 73 61 66 74 } //1 \Run\360saft
		$a_01_1 = {66 69 72 65 68 61 63 6b 72 40 71 71 2e 63 6f 6d } //1 firehackr@qq.com
		$a_03_2 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c ?? 65 2e 65 78 65 } //1
		$a_03_3 = {30 30 30 2b 2b 2b ?? 66 69 72 65 68 61 63 6b 72 ?? 73 6d 74 70 2e 71 71 2e 63 6f 6d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}