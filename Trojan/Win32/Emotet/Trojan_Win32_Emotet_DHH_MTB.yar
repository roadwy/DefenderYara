
rule Trojan_Win32_Emotet_DHH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 16 8b 54 24 3c 8a 24 0a 28 c4 [0-1b] 88 24 0e 8a 64 24 13 30 e0 8b 7c 24 0c 88 44 3c 50 } //1
		$a_00_1 = {8a 0c 02 8b 75 ec 81 ce 0c f7 e1 00 89 75 ec 66 8b 7d ea 66 89 7d ea 8b 75 dc 88 0c 06 8a 4d f3 8a 6d f3 83 c0 01 08 e9 88 4d f3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}