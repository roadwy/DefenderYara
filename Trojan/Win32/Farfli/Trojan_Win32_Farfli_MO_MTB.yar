
rule Trojan_Win32_Farfli_MO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 e8 83 c2 01 89 55 e8 8b 45 e8 3b 45 0c 73 ?? 8b 4d 08 8a 11 32 55 ec 8b 45 08 88 10 8b 4d 08 8a 11 02 55 ec 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb } //1
		$a_02_1 = {56 8b 74 24 0c 57 56 e8 ?? ?? ?? ?? ff 4e 04 59 78 0f 8b 0e 8a 44 24 0c 0f b6 f8 88 01 ff 06 eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}