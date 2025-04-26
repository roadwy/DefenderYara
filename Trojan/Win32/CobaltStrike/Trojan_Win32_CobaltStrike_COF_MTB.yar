
rule Trojan_Win32_CobaltStrike_COF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.COF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 08 88 14 08 b9 d6 67 17 00 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 35 ca 2c 10 00 0f af 87 b4 00 00 00 89 87 b4 00 00 00 8b 87 fc 00 00 00 } //1
		$a_03_1 = {03 87 c8 00 00 00 09 87 a4 00 00 00 a1 ?? ?? ?? ?? 2b 88 b4 00 00 00 2b 8f c0 00 00 00 01 8f 0c 01 00 00 a1 ?? ?? ?? ?? 8b 8f 88 00 00 00 88 1c 08 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 87 c0 00 00 00 81 fd 58 23 00 00 0f 8c 50 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}