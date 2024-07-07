
rule Trojan_AndroidOS_Fakecalls_I{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.I,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {6c 65 74 73 63 61 6c 6c 2d 6d 73 67 } //2 letscall-msg
		$a_00_1 = {2f 61 70 70 2f 75 6e 62 69 6e 64 2d 61 67 65 6e 74 } //2 /app/unbind-agent
		$a_00_2 = {65 6e 61 62 6c 65 64 5f 63 61 6c 6c 5f 77 68 69 74 65 6c 69 73 74 73 } //2 enabled_call_whitelists
		$a_01_3 = {69 73 44 65 66 61 75 6c 74 50 68 6f 6e 65 43 61 6c 6c 41 70 70 } //2 isDefaultPhoneCallApp
		$a_00_4 = {2f 61 70 70 2f 61 70 70 6c 79 2d 61 64 64 } //2 /app/apply-add
		$a_00_5 = {64 65 76 65 6c 6f 70 5f 61 70 6b 2f 61 70 70 5f 73 69 67 6e 2e 61 70 6b } //2 develop_apk/app_sign.apk
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=8
 
}