
rule Trojan_Win32_Convagent_REV_MTB{
	meta:
		description = "Trojan:Win32/Convagent.REV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 8b c7 c1 e8 05 03 d7 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c 8b f7 c1 e6 04 03 b5 b0 fd ff ff 33 f2 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}