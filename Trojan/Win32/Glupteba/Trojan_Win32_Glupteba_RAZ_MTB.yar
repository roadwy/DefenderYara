
rule Trojan_Win32_Glupteba_RAZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8b cf c1 e1 04 03 4c 24 2c 8b c7 c1 e8 05 03 44 24 38 8d 14 3b 33 ca 89 44 24 1c 89 4c 24 14 89 35 ?? ?? ?? ?? 8b 44 24 1c 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 30 89 74 24 1c 8b 44 24 30 01 44 24 1c 8b 44 24 14 33 44 24 1c 89 44 24 1c 8b 4c 24 1c } //1
		$a_01_1 = {33 f5 33 c6 2b f8 81 c3 47 86 c8 61 ff 4c 24 24 89 44 24 14 0f 85 fd fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}