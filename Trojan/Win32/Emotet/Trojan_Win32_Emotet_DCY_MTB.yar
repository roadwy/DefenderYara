
rule Trojan_Win32_Emotet_DCY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 8d 44 24 90 01 01 50 ff d3 50 ff d5 8b 4c 24 90 01 01 8b 54 24 90 01 01 8b 44 24 90 01 01 51 52 50 ff d7 8b 4c 24 90 01 01 8b 44 24 90 01 01 83 c4 0c 51 8b 4c 24 90 01 01 8d 54 24 90 01 01 52 50 6a 00 6a 01 6a 00 51 ff 54 24 90 01 01 5f 90 00 } //1
		$a_02_1 = {6a 40 68 00 10 00 00 50 57 ff 54 24 90 01 01 8b 4c 24 90 01 01 8b 54 24 90 01 01 51 8b f0 52 56 ff d5 8b 84 24 90 02 04 8b 54 24 90 01 01 83 c4 0c 50 8d 4c 24 90 01 01 51 56 57 6a 01 57 52 ff 54 24 90 01 01 f7 d8 5f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}