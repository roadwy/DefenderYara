
rule Trojan_Win32_Reconyc_GVD_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 73 6e 69 70 70 65 74 2e 68 6f 73 74 2f 77 74 62 74 65 77 2f 72 61 77 75 31 5b 44 45 42 55 47 5d 20 55 31 3a 20 } //1 ://snippet.host/wtbtew/rawu1[DEBUG] U1: 
		$a_01_1 = {63 68 65 63 6b 5f 75 70 64 61 74 65 5f 75 72 6c 3a } //1 check_update_url:
		$a_01_2 = {66 65 74 63 68 5f 75 72 6c 3a } //1 fetch_url:
		$a_01_3 = {41 6e 74 69 2d 62 6f 74 } //1 Anti-bot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}