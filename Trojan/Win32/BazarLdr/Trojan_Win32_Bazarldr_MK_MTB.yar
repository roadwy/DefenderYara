
rule Trojan_Win32_Bazarldr_MK_MTB{
	meta:
		description = "Trojan:Win32/Bazarldr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e ba [0-02] 00 00 0f b6 c0 2b d0 8d 04 92 c1 e0 [0-01] 99 f7 ff 8d 42 [0-01] 99 f7 ff 88 14 0e 46 83 fe [0-01] 72 } //2
		$a_03_1 = {8a 04 0e ba [0-02] 00 00 0f b6 c0 2b d0 6b c2 [0-01] 99 f7 ff 8d 42 [0-01] 99 f7 ff 88 14 0e 46 83 fe [0-01] 72 } //2
		$a_03_2 = {8a 44 35 e8 b9 [0-02] 00 00 0f b6 c0 2b c8 8d 04 c9 03 c0 99 f7 ff 8d 42 [0-01] 99 f7 ff 88 54 [0-02] 46 83 fe [0-01] 72 } //2
		$a_03_3 = {0f b6 c0 83 e8 [0-01] 8d 04 80 03 c0 99 f7 fb 8d 42 [0-01] 99 f7 fb 88 94 0d [0-04] 41 83 f9 [0-01] 72 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=2
 
}