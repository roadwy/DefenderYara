
rule Trojan_Win32_Vidar_BK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c7 f7 f1 8b 85 [0-04] 8a 0c 02 8b 95 [0-04] 32 0c 1a 8d 85 [0-04] 50 88 0b e8 [0-04] 83 c4 04 8d 8d [0-04] 51 ff d6 8b 9d [0-03] ff 47 3b bd [0-04] 72 } //3
		$a_01_1 = {53 56 6a 04 68 00 30 00 00 68 c0 41 c8 17 6a 00 ff 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}