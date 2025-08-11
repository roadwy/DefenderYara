
rule Trojan_Win32_PureCrypter_NIT_MTB{
	meta:
		description = "Trojan:Win32/PureCrypter.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 45 95 fc ff 87 d3 81 c3 78 42 3b 20 f7 df 33 05 39 14 4d 00 81 3d 30 0f 4d 00 d4 65 47 98 72 02 f7 d8 c1 e2 0d 81 f7 82 1b d2 43 c1 ea 0d 01 05 75 09 4f 00 87 c7 48 33 c7 ff c9 75 c2 } //3
		$a_01_1 = {8b 1d 65 60 4c 00 48 f7 d8 8b fa f7 d8 c1 eb 1e c1 e0 06 03 15 8c 9b 4e 00 c1 c8 16 f7 d0 ff c9 75 de } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}