
rule Trojan_Win32_ForestTiger_A_dha{
	meta:
		description = "Trojan:Win32/ForestTiger.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b8 55 b9 db 02 eb 90 01 01 41 8b c8 c1 e1 05 41 8b c0 c1 f8 02 03 c8 40 0f be c7 03 c8 44 33 c1 48 ff c2 90 00 } //100
		$a_03_1 = {ba 55 b9 db 02 84 c9 74 90 01 01 8d 64 24 00 8b fa 8b da c1 e7 05 c1 fb 02 0f be c9 03 fb 03 f9 8a 4e 01 46 33 d7 90 00 } //100
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100) >=100
 
}