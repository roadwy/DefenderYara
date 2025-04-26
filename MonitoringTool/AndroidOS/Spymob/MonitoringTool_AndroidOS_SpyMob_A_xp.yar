
rule MonitoringTool_AndroidOS_SpyMob_A_xp{
	meta:
		description = "MonitoringTool:AndroidOS/SpyMob.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 70 79 32 6d 6f 62 69 6c 65 2f } //1 com/spy2mobile/
		$a_01_1 = {63 6f 6d 2e 6f 67 70 2e 73 79 73 63 6f 6d 70 72 6f 63 65 73 73 6f 72 2e 41 43 54 49 4f 4e } //1 com.ogp.syscomprocessor.ACTION
		$a_01_2 = {3c 54 4b 3b 54 56 3b 3e 2e 4b 65 79 53 65 74 3b } //1 <TK;TV;>.KeySet;
		$a_01_3 = {43 6f 6e 6e 65 63 74 69 76 69 74 79 20 63 68 61 6e 67 65 64 2e 20 53 74 61 72 74 69 6e 67 20 62 61 63 6b 67 72 6f 75 6e 64 20 73 79 6e 63 } //1 Connectivity changed. Starting background sync
		$a_00_4 = {68 74 74 70 3a 2f 2f 75 6f 6e 6d 61 70 2e 63 6f 6d 2f } //1 http://uonmap.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}