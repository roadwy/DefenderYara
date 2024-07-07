
rule Trojan_Win32_Emotet_DEC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 90 01 04 f7 f9 8a 04 2b 8a 54 14 90 01 01 32 c2 88 04 2b 8b 84 24 90 02 09 85 c0 0f 85 90 00 } //1
		$a_81_1 = {41 30 6b 42 74 42 4a 4f 4c 6e 59 58 35 49 6c 6b 56 46 68 62 48 46 74 30 72 57 44 79 4d 68 43 45 42 6d 6b 47 } //1 A0kBtBJOLnYX5IlkVFhbHFt0rWDyMhCEBmkG
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}