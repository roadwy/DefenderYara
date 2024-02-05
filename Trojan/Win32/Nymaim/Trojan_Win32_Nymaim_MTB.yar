
rule Trojan_Win32_Nymaim_MTB{
	meta:
		description = "Trojan:Win32/Nymaim!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c2 04 83 c6 90 01 01 c1 ce 08 29 ce 83 c6 ff 31 c9 09 f1 c1 c1 0a c1 c9 02 c7 07 00 00 00 00 01 37 83 c7 04 8d 5b 04 81 fb 88 06 00 00 75 cf 5f 8b 0d 90 01 03 00 51 89 3d 90 01 03 00 ff 15 90 00 } //01 00 
		$a_02_1 = {83 c3 04 83 c7 90 01 01 c1 cf 08 29 d7 83 c7 ff 57 5a c1 c2 90 01 01 c1 ca 90 01 01 c7 06 00 00 00 00 01 3e 83 ee fc 83 e8 fc 3d 88 06 00 00 75 90 01 01 5e 8b 0d 90 01 03 00 51 89 35 90 01 03 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}