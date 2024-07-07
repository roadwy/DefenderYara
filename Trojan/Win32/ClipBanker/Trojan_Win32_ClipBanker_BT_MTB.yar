
rule Trojan_Win32_ClipBanker_BT_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 07 83 f8 60 76 90 01 01 83 f8 7b 72 90 01 01 83 f8 40 76 90 01 01 83 f8 5b 72 90 01 01 83 f8 2f 76 90 01 01 83 f8 3a 73 90 00 } //2
		$a_03_1 = {0f b7 07 66 3b 45 f0 76 90 01 01 66 3b 45 e0 72 90 01 01 66 3b 45 e8 76 90 01 01 66 3b 45 f4 72 90 01 01 66 3b 45 ec 76 90 01 01 66 3b 45 e4 73 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}