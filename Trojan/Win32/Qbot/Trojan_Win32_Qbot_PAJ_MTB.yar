
rule Trojan_Win32_Qbot_PAJ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 3c 31 88 1c 11 0f b6 0c 31 01 f9 81 ?? ff 00 00 00 8b 7c 24 ?? 8b 74 24 ?? 8a 1c 37 8b 74 24 ?? 32 1c 0e 8b 4c 24 ?? 8b 74 24 ?? 88 1c 31 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}