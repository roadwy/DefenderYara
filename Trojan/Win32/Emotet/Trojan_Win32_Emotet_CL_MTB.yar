
rule Trojan_Win32_Emotet_CL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 08 83 c4 0c 33 d2 84 c9 74 90 01 01 8b ea c1 e5 13 c1 ea 0d 0b d5 80 f9 61 0f b6 c9 72 90 01 01 83 e9 20 03 d1 8a 48 01 40 84 c9 75 90 00 } //1
		$a_02_1 = {6a 00 ff 15 90 01 04 c7 05 90 01 04 03 80 00 00 c7 05 90 01 04 01 68 00 00 c7 05 90 01 04 01 00 00 00 c7 05 90 01 04 40 00 00 00 c7 05 90 01 04 00 10 00 00 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}