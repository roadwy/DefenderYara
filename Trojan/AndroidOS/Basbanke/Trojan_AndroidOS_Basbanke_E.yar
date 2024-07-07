
rule Trojan_AndroidOS_Basbanke_E{
	meta:
		description = "Trojan:AndroidOS/Basbanke.E,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 61 6e 64 6c 65 49 62 6b 35 4c 69 6e 65 73 53 6d 73 4e 6f 42 61 6c 61 6e 63 65 } //2 HandleIbk5LinesSmsNoBalance
		$a_01_1 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 47 65 74 41 6e 64 53 79 6e 63 4c 61 74 65 73 74 4d 65 73 73 61 67 65 73 } //2 ResumableSub_GetAndSyncLatestMessages
		$a_01_2 = {64 65 70 6f 73 69 74 2d 73 79 73 74 65 6d 2f 61 70 69 2f 6c 6f 67 2e 70 68 70 } //2 deposit-system/api/log.php
		$a_01_3 = {5f 73 69 6e 63 65 64 61 74 65 74 69 6d 65 } //2 _sincedatetime
		$a_01_4 = {5f 6d 69 6e 5f 70 61 72 73 65 64 5f 64 61 74 61 5f 66 69 65 6c 64 73 5f 66 6f 72 5f 73 79 6e 63 } //2 _min_parsed_data_fields_for_sync
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}