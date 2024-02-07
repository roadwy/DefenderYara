
rule TrojanSpy_AndroidOS_YangaMon_A{
	meta:
		description = "TrojanSpy:AndroidOS/YangaMon.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 2e 66 7a 62 6b 2e 69 6e 66 6f 2f 41 6e 64 72 6f 69 64 49 6e 74 65 72 66 61 63 65 2f 52 65 67 2e 61 73 70 78 } //01 00  android.fzbk.info/AndroidInterface/Reg.aspx
		$a_01_1 = {4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 2e 62 65 67 69 6e 46 65 65 } //01 00  MonitorService.beginFee
		$a_01_2 = {73 6d 73 46 65 65 49 6e 66 6f } //01 00  smsFeeInfo
		$a_01_3 = {68 61 69 79 61 6e 67 3a 63 72 65 61 74 65 64 62 3d } //00 00  haiyang:createdb=
	condition:
		any of ($a_*)
 
}