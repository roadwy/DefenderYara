
rule Backdoor_Script_RogueSpy_F_dha{
	meta:
		description = "Backdoor:Script/RogueSpy.F!dha,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 78 00 } //1 curl.exe -x
		$a_00_1 = {73 00 6f 00 63 00 6b 00 73 00 35 00 68 00 3a 00 2f 00 2f 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 3a 00 39 00 30 00 35 00 30 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1 socks5h://127.0.0.1:9050 http://
		$a_00_2 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 } //1 .onion
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}