
rule Trojan_Win32_Farfli_PA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 08 88 4d f0 8b 55 08 03 55 fc 8b 45 08 03 45 f8 8a 08 88 0a 8b 55 08 03 55 f8 8a 45 f0 88 02 8b 4d 08 03 4d fc 33 d2 8a 11 8b 45 08 03 45 f8 33 c9 8a 08 03 d1 81 e2 ff 00 00 80 79 } //1
		$a_02_1 = {4a 81 ca 00 ff ff ff 42 89 55 f4 8b 55 0c 03 55 ec 8b 45 08 03 45 f4 8a 0a 32 08 8b 55 0c 03 55 ec 88 0a e9 ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}