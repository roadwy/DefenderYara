
rule TrojanDropper_AndroidOS_SMSAgent_B_xp{
	meta:
		description = "TrojanDropper:AndroidOS/SMSAgent.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 32 63 6a 6c 6e 59 57 31 6c 4c 6d 4e 76 62 51 3d 3d } //1 aHR0cDovL3d3dy52cjlnYW1lLmNvbQ==
		$a_00_1 = {64 69 6c 79 73 2e 63 6f 6d 2e 63 6e 3a 39 39 33 35 2f 63 7a 7a 71 6c 2f 63 6c 69 65 6e 74 2f 72 65 63 65 69 76 65 } //1 dilys.com.cn:9935/czzql/client/receive
		$a_00_2 = {6c 79 73 6d 73 2e 64 65 } //1 lysms.de
		$a_00_3 = {77 65 62 2e 69 64 6d 7a 6f 6e 65 2e 63 6f 6d } //1 web.idmzone.com
		$a_00_4 = {4d 6f 62 63 6c 69 63 6b 41 67 65 6e 74 2e 6a 61 76 61 20 } //1 MobclickAgent.java 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}