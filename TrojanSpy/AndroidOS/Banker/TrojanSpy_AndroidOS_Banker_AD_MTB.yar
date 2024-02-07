
rule TrojanSpy_AndroidOS_Banker_AD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 68 6f 6e 65 6c 69 73 74 65 6e 65 72 } //01 00  phonelistener
		$a_00_1 = {62 61 6e 6b 69 6e 69 64 } //01 00  bankinid
		$a_00_2 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 4e 50 4b 49 } //01 00  /mnt/sdcard/NPKI
		$a_00_3 = {6c 69 75 6a 75 6e 31 39 39 30 36 37 40 31 32 36 2e 63 6f 6d } //01 00  liujun199067@126.com
		$a_00_4 = {4e 48 41 63 6f 75 6e 74 49 6e 66 6f } //00 00  NHAcountInfo
		$a_00_5 = {5d 04 00 } //00 0c 
	condition:
		any of ($a_*)
 
}