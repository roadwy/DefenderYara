
rule Trojan_Win32_Emotet_DPS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 0f be 04 01 50 ff 74 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 59 59 8b 4c 24 10 88 04 11 90 09 04 00 8b 44 24 } //2
		$a_02_1 = {8b 6c 24 14 8b 4c 24 ?? 8b 44 24 1c 0f be 14 29 52 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 83 c4 08 88 04 29 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}