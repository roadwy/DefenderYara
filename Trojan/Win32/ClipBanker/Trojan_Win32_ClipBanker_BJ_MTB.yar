
rule Trojan_Win32_ClipBanker_BJ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 ff 15 ac a3 40 00 85 c0 74 90 01 01 53 57 ff 15 a8 a3 40 00 8b 86 8c 04 00 00 8b 40 f8 40 50 68 00 20 00 00 ff 15 48 a0 40 00 8b d8 53 ff 15 90 00 } //2
		$a_01_1 = {b9 d0 11 42 47 a0 22 3f 5b ca 30 94 0e 2a 85 09 5a 82 f1 fb 68 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}