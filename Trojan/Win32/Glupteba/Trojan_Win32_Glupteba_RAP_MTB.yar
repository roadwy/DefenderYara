
rule Trojan_Win32_Glupteba_RAP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 05 03 d5 8b c8 c1 e1 04 89 54 24 20 03 cb 8d 14 06 33 ca 89 4c 24 10 89 3d ?? ?? ?? ?? 8b 44 24 20 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 38 89 7c 24 20 } //1
		$a_03_1 = {31 7c 24 10 8b 44 24 20 31 44 24 10 8b 44 24 10 29 44 24 1c c7 44 24 18 ?? ?? ?? ?? 8b 44 24 34 01 44 24 18 2b 74 24 18 ff 4c 24 2c 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}