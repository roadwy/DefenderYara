
rule Trojan_Win32_Ekstak_BD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 45 08 8b 0d ?? ?? ?? ?? 8a 14 08 32 15 ?? ?? ?? ?? 8b 45 0c 03 45 08 8b 0d ?? ?? ?? ?? 88 14 08 83 3d ?? ?? ?? ?? 03 76 ?? 8b 55 08 83 c2 01 89 55 08 eb ?? cc 81 7d 08 04 05 00 00 7e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}