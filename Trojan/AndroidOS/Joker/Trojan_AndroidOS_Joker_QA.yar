
rule Trojan_AndroidOS_Joker_QA{
	meta:
		description = "Trojan:AndroidOS/Joker.QA,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 76 69 6e 61 3d 32 70 6f 73 74 } //01 00  evina=2post
		$a_01_1 = {6e 65 78 74 70 6f 72 74 61 6c 2e 68 6c 69 66 65 70 6c 75 73 2e 63 6f 6d 2f 77 61 70 2f 61 70 69 5f 61 6f 63 } //01 00  nextportal.hlifeplus.com/wap/api_aoc
		$a_01_2 = {77 65 62 2d 7a 6d 64 2e 73 65 63 75 72 65 2d 64 2e 69 6f 2f 61 70 69 2f 76 32 2f 61 63 74 69 76 61 74 65 } //01 00  web-zmd.secure-d.io/api/v2/activate
		$a_01_3 = {4d 43 50 5f 4f 55 54 4c 49 4e 45 5f 4b 45 59 } //01 00  MCP_OUTLINE_KEY
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 64 65 74 65 63 74 20 69 6e 63 6c 69 6e 65 20 6d 63 70 20 63 6f 64 65 } //01 00  Failed to detect incline mcp code
		$a_01_5 = {63 70 5f 63 61 6c 6c 5f 63 65 6e 74 65 72 5f 6e 75 6d 62 65 72 } //01 00  cp_call_center_number
		$a_01_6 = {4d 43 50 5f 53 49 54 45 2e 72 2e 73 68 69 65 6c 64 2e 6d 6f 6e 69 74 6f 72 69 6e 67 73 65 72 76 69 63 65 2e 63 6f 2f 70 2e 70 6e 67 } //00 00  MCP_SITE.r.shield.monitoringservice.co/p.png
		$a_00_7 = {5d 04 00 } //00 3c 
	condition:
		any of ($a_*)
 
}