
rule Trojan_Win32_Daonol_M{
	meta:
		description = "Trojan:Win32/Daonol.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 8d 4d d0 90 02 0a 66 4b 90 02 0a ff 34 37 90 02 0a 33 41 fc 90 02 0a 46 90 02 0a c1 e0 08 90 02 0a 88 64 37 ff 90 02 0a 4f 90 02 0a 75 90 00 } //1
		$a_03_1 = {8d 4d d0 66 4b 90 02 0a ff 34 37 90 02 0a 8b 49 fc 90 02 0a 31 c8 90 02 0a 90 17 03 0c 06 06 46 90 02 0a c1 90 04 01 02 e0 c0 08 d3 c8 90 02 0a 46 46 90 02 0a d3 c8 90 02 0a 88 90 04 01 02 64 44 37 ff 90 02 0a 4f 90 02 0a 75 90 14 90 02 0a 46 90 02 0a 90 03 01 01 81 83 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}