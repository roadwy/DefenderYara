
rule Backdoor_AndroidOS_Luckycat_B{
	meta:
		description = "Backdoor:AndroidOS/Luckycat.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 63 72 65 61 74 65 20 73 6f 63 6b 65 74 20 6f 6b 21 } //01 00  +create socket ok!
		$a_01_1 = {21 4c 63 6f 6d 2f 62 61 69 64 75 2f 6d 61 70 61 70 69 2f 54 72 61 6e 73 69 74 4f 76 65 72 6c 61 79 } //01 00  !Lcom/baidu/mapapi/TransitOverlay
		$a_01_2 = {26 63 68 6d 6f 64 20 2d 52 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 74 65 6e 63 65 6e 74 2e 6d 6d } //01 00  &chmod -R 777 /data/data/com.tencent.mm
		$a_01_3 = {63 68 6d 6f 64 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 } //01 00  chmod 777 /data/data
		$a_01_4 = {73 6f 63 6b 65 20 63 6c 6f 73 65 } //00 00  socke close
	condition:
		any of ($a_*)
 
}