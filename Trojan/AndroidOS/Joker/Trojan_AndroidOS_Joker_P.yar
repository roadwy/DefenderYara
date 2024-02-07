
rule Trojan_AndroidOS_Joker_P{
	meta:
		description = "Trojan:AndroidOS/Joker.P,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 6f 30 2e 6f 73 73 2d 61 63 63 65 6c 65 72 61 74 65 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f 61 64 61 6c 2e 6a 61 72 } //01 00  wo0.oss-accelerate.aliyuncs.com/adal.jar
		$a_00_1 = {63 6f 6d 2e 61 6e 74 75 6d 65 2e 43 61 6e 74 69 6e } //01 00  com.antume.Cantin
		$a_00_2 = {69 6f 5f 66 76 2e 6c 6f 67 } //00 00  io_fv.log
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}