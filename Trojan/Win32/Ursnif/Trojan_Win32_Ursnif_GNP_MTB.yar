
rule Trojan_Win32_Ursnif_GNP_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 0f b6 d3 83 e1 0f c1 ea 04 33 ca c1 e8 04 33 04 8e 83 7d fc } //10
		$a_01_1 = {35 40 8c fa ae 8b 0f 8b 56 f4 03 4d 08 89 45 fc } //10
		$a_01_2 = {32 36 39 65 33 38 36 33 2e 64 6c 6c } //1 269e3863.dll
		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}