
rule Trojan_Win32_Emotet_DCP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 33 d2 b9 90 01 04 f7 f1 8b 45 90 01 01 0f be 0c 10 8b 55 90 01 01 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //1
		$a_02_1 = {6a 00 6a 00 ff 15 90 01 04 8b 45 fc 33 d2 b9 90 01 04 f7 f1 8b 45 90 01 01 03 45 90 01 01 8b 4d 90 01 01 8a 00 32 04 11 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}