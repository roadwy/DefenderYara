
rule Misleading_AndroidOS_Dnotua_C_MTB{
	meta:
		description = "Misleading:AndroidOS/Dnotua.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 2e 74 6f 70 62 65 72 2e 63 6f 6d } //01 00  m.topber.com
		$a_00_1 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 2f 6d 79 61 70 70 6c 69 63 61 74 69 6f 6e } //01 00  com/example/administrator/myapplication
		$a_00_2 = {77 65 69 78 69 6e 3a 2f 2f } //01 00  weixin://
		$a_00_3 = {64 69 61 6e 70 69 6e 67 3a 2f 2f } //01 00  dianping://
		$a_00_4 = {61 6c 69 70 61 79 73 3a 2f 2f } //00 00  alipays://
	condition:
		any of ($a_*)
 
}