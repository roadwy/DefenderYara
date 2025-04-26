
rule Trojan_Win32_Zbot_RN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f8 c8 db 00 00 8b 05 ?? ?? ?? ?? 89 45 dc 8b ?? dc 89 ?? e0 8b ?? e0 89 ?? e4 8b ?? e4 89 ?? e8 8b ?? 08 8b 55 08 03 55 f0 8b ?? 33 ?? e8 03 ?? f0 89 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}