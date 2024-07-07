
rule Trojan_AndroidOS_Ztorg_A_xp{
	meta:
		description = "Trojan:AndroidOS/Ztorg.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 64 64 6c 69 6f 6e 73 2e 74 68 75 6e 64 65 72 } //1 com.ddlions.thunder
		$a_01_1 = {63 6f 6d 2e 6b 6f 6b 2e 64 64 6c 69 6f 6e 73 2e 66 72 61 6d 65 2e 53 74 61 72 74 53 65 72 76 69 63 65 } //2 com.kok.ddlions.frame.StartService
		$a_01_2 = {63 6f 6d 2e 79 65 61 68 2e 64 6f 77 6e 6c 6f 61 64 2e 41 43 54 49 4f 4e 5f 44 4f 57 4e 4c 4f 41 44 5f 53 54 41 52 54 } //1 com.yeah.download.ACTION_DOWNLOAD_START
		$a_01_3 = {2e 62 6c 75 65 73 6b 79 73 7a 2e 63 6f 6d 3a 39 38 38 34 2f 6e 65 77 73 65 72 76 69 63 65 2f 6e 65 77 62 61 63 6b 44 61 74 61 73 2e 61 63 74 69 6f 6e } //1 .blueskysz.com:9884/newservice/newbackDatas.action
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}