
rule Trojan_Win32_BlueFox_RPK_MTB{
	meta:
		description = "Trojan:Win32/BlueFox.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 0c 73 2c 8b 45 08 03 45 f4 0f b6 08 8b 55 f4 81 e2 ?? ?? ?? ?? 79 05 4a 83 ca f0 42 8b 45 fc 0f b6 14 10 33 ca 8b 45 f8 03 45 f4 88 08 eb c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}