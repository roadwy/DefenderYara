
rule Trojan_Win32_Ursnif_BT_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 44 10 05 2b cb a3 90 01 04 a1 90 01 04 8d 71 b8 8b 4c 24 10 05 90 01 04 89 01 0f b7 fe a3 90 01 04 8d 47 40 99 8b c8 0f b6 05 90 01 04 66 89 35 90 01 04 8b ea 66 3b c6 73 90 00 } //1
		$a_02_1 = {8b c1 2b c7 83 e8 48 88 15 90 01 04 a3 90 01 04 0f b7 15 90 01 04 8b c7 2b c2 83 c0 40 99 03 c8 13 ea 83 44 24 10 04 ff 4c 24 14 0f 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}