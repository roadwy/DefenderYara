
rule Trojan_Win32_Trickbot_RAS_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ca 00 ff ff ff 42 8a 4c 14 ?? 8b 54 24 ?? 8a 1c 3a 8b 44 24 ?? 32 cb 88 0f 47 48 89 44 24 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}