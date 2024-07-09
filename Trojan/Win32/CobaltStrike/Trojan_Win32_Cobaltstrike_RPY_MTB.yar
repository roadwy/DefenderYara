
rule Trojan_Win32_Cobaltstrike_RPY_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 e0 31 f6 89 75 e0 89 44 24 0c c7 44 24 08 40 00 00 00 89 5c 24 04 8b 45 08 89 04 24 a1 ?? ?? ?? ?? 89 45 d4 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}