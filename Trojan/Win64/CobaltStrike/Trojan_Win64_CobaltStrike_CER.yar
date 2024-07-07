
rule Trojan_Win64_CobaltStrike_CER{
	meta:
		description = "Trojan:Win64/CobaltStrike.CER,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 73 63 5f 55 55 49 44 53 2e 64 6c 6c } //1 wsc_UUIDS.dll
		$a_01_1 = {44 3a 5c 70 72 6f 6a 65 63 74 5c 64 6f 67 65 2d 63 6c 6f 75 64 5c 74 61 72 67 65 74 66 69 6c 65 73 } //1 D:\project\doge-cloud\targetfiles
		$a_01_2 = {6f 6e 5f 61 76 61 73 74 5f 64 6c 6c 5f 75 6e 6c 6f 61 64 } //1 on_avast_dll_unload
		$a_03_3 = {0f 1f 44 00 00 83 f9 0a 0f 4c c2 3d 90 01 04 7e 90 01 01 3d 90 01 04 0f 90 01 05 3d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}