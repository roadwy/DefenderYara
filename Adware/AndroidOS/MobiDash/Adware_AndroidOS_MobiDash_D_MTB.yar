
rule Adware_AndroidOS_MobiDash_D_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {60 00 98 00 6f 20 ec 09 98 00 6e 10 91 0f 08 00 52 81 dc 01 b7 91 59 89 dc 01 dd 02 09 04 12 03 12 14 39 02 04 00 12 12 28 02 } //1
		$a_01_1 = {62 39 37 62 35 36 63 38 64 62 61 66 37 30 39 63 32 34 30 62 63 61 61 30 32 36 66 61 34 37 61 61 2e 63 6f 6d } //1 b97b56c8dbaf709c240bcaa026fa47aa.com
		$a_01_2 = {68 69 64 65 5f 61 70 70 5f 69 63 6f 6e } //1 hide_app_icon
		$a_01_3 = {24 74 68 69 73 24 67 65 74 69 6e 73 74 61 6c 6c 64 61 74 65 } //1 $this$getinstalldate
		$a_01_4 = {45 6e 64 6c 65 73 73 53 65 72 76 69 63 65 3a 3a 6c 6f 63 6b } //1 EndlessService::lock
		$a_01_5 = {53 53 52 65 63 65 69 76 65 72 50 72 6f 78 79 } //1 SSReceiverProxy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}