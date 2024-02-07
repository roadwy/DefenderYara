
rule Backdoor_AndroidOS_Fakengry_A{
	meta:
		description = "Backdoor:AndroidOS/Fakengry.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 26 74 61 73 6b 3d 77 69 6e 64 6f 77 26 64 6f 77 6e 6c 6f 61 64 54 79 70 65 3d 73 69 6c 65 6e 74 64 6f 77 6e 6c 6f 61 64 26 66 6c 61 67 69 64 3d 2d 31 30 31 26 73 6f 66 74 75 69 64 3d } //01 00  =&task=window&downloadType=silentdownload&flagid=-101&softuid=
		$a_01_1 = {6c 2e 61 6e 7a 68 75 6f 37 2e 63 6f 6d 3a 39 30 35 35 2f 63 61 2e 6c 6f 67 } //01 00  l.anzhuo7.com:9055/ca.log
		$a_01_2 = {3a 38 30 39 37 2f 67 65 74 78 6d 6c 2e 64 6f } //01 00  :8097/getxml.do
		$a_01_3 = {69 32 32 2f 61 6e 67 72 79 62 69 72 64 73 2f 63 63 63 63 63 63 } //01 00  i22/angrybirds/cccccc
		$a_01_4 = {03 e8 af b7 e7 a8 8d e4 be af 00 08 e6 95 b0 e6 8d ae e6 b8 85 e7 90 86 e4 b8 ad 2e 2e 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}