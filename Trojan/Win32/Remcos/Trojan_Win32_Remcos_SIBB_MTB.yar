
rule Trojan_Win32_Remcos_SIBB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 85 db 7e ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 2b 45 ?? 5a 8b ca 99 f7 f9 8b 45 ?? 8b 0d ?? ?? ?? ?? 0f b6 44 08 ?? 03 d0 8d 45 ?? e8 39 0b fa ?? 8b 55 ?? 8b c6 e8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 4b 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}