
rule Trojan_Win32_Emotet_OG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.OG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e2 ff 00 00 00 89 90 02 05 8b 90 02 05 8a 90 02 02 30 90 02 02 8b 90 02 05 8b 90 02 05 8a 90 02 02 30 90 02 02 8b 90 02 05 8b 90 02 05 8a 90 02 02 30 90 02 02 ff 90 02 05 8b 90 02 05 3d 90 02 64 81 90 01 01 ff 00 00 00 90 02 4b 30 90 02 4b 30 90 00 } //1
		$a_02_1 = {6a 40 68 00 10 00 00 90 02 23 83 c4 0c 90 02 23 6a 00 6a 01 6a 00 90 02 96 83 c4 0c 90 02 0f ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}