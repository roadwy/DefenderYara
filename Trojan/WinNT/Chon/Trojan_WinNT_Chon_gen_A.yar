
rule Trojan_WinNT_Chon_gen_A{
	meta:
		description = "Trojan:WinNT/Chon.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {99 f7 7d 0c 8b 45 08 8a 04 02 32 01 32 45 14 46 3b 75 14 88 01 7c e1 } //1
		$a_01_1 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 58 8b 45 08 8b 4d fc 89 08 } //1
		$a_03_2 = {83 4d f4 ff 33 90 01 01 c7 45 f0 00 1f 0a fa 33 90 02 08 75 12 8d 45 f0 50 90 01 02 ff 15 90 01 02 01 00 90 01 01 83 90 01 01 1e 72 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}