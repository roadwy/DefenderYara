
rule Trojan_Win64_Winnti_ZA_dha{
	meta:
		description = "Trojan:Win64/Winnti.ZA!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 8a 1f b8 01 00 00 00 41 8d 0c 03 48 63 d0 ff c0 30 0c 3a 3b c3 72 f0 bb 3a 11 00 00 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d3 33 c9 ff 15 } //1
		$a_01_1 = {67 5f 74 68 72 65 61 64 5f 6a 6f 69 6e } //1 g_thread_join
		$a_01_2 = {67 74 68 72 65 61 64 2d 32 2e 32 2e 64 6c 6c } //1 gthread-2.2.dll
		$a_02_3 = {63 6d 64 2e 65 78 65 20 2f 43 20 22 43 3a 5c 54 45 4d 50 5c [0-0a] 2e 74 6d 70 2e 62 61 74 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}