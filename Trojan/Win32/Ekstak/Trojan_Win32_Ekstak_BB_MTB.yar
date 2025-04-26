
rule Trojan_Win32_Ekstak_BB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 11 88 0c ?? 8a 8a ?? ?? ?? ?? 84 c9 75 12 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 76 03 42 eb } //1
		$a_02_1 = {60 2b f0 86 c3 83 fe 39 8d 3d ?? ?? ?? ?? 88 07 03 07 ba 0d 00 00 00 83 e6 3a 66 8b c3 83 f9 0e 61 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}