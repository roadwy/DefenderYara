
rule Trojan_AndroidOS_Riltok_B{
	meta:
		description = "Trojan:AndroidOS/Riltok.B,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 54 54 50 5f 52 45 51 5f 45 4e 54 49 54 59 5f 4a 4f 49 4e } //2 HTTP_REQ_ENTITY_JOIN
		$a_01_1 = {73 65 6e 64 48 69 74 47 61 74 65 41 50 49 52 65 71 75 65 73 74 } //2 sendHitGateAPIRequest
		$a_01_2 = {72 65 71 75 65 73 74 73 2f 48 69 74 47 61 74 65 52 65 71 75 65 73 74 } //2 requests/HitGateRequest
		$a_01_3 = {67 65 74 50 6f 73 74 50 61 72 61 6d 73 55 54 46 38 } //2 getPostParamsUTF8
		$a_00_4 = {67 61 74 69 6e 67 2e 70 68 70 } //1 gating.php
		$a_00_5 = {67 61 74 65 2e 70 68 70 } //1 gate.php
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}