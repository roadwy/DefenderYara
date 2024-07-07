
rule Trojan_WinNT_Regin_gen_C{
	meta:
		description = "Trojan:WinNT/Regin.gen.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 0c 8b 40 64 c1 e8 02 50 ff 75 0c e8 } //1
		$a_01_1 = {6a 41 eb 02 6a 46 5e ff 75 f8 e8 } //1
		$a_03_2 = {8b 40 28 6a 00 03 90 05 01 03 c0 2d c7 90 05 01 03 50 2d 57 ff d0 f7 d8 1a c0 90 02 02 fe c0 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}