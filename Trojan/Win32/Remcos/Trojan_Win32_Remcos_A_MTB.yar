
rule Trojan_Win32_Remcos_A_MTB{
	meta:
		description = "Trojan:Win32/Remcos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ff ff 8b 55 ?? 30 04 3a 47 4b 0f 85 ?? ff ff ff } //1
		$a_00_1 = {8b 45 fc 8a 04 38 8b 55 e8 88 04 3a 47 4b 75 f0 } //1
		$a_00_2 = {89 38 47 83 c0 04 81 ff 00 01 00 00 75 e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}