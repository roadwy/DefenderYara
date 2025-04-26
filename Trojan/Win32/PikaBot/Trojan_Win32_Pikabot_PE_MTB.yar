
rule Trojan_Win32_Pikabot_PE_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f6 0f b6 54 15 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 eb ?? 8b 4d ?? 51 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}