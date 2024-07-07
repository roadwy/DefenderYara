
rule Trojan_Win32_Qbot_DHC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fe 8b 7c 24 90 01 01 8a 1c 17 0f b6 fb 89 4c 24 90 01 01 8b 4c 24 90 01 01 01 f9 89 c8 89 54 24 90 01 01 99 f7 fe 90 00 } //1
		$a_02_1 = {01 fe 21 de 8b 7c 24 90 01 01 32 0c 37 8b 74 24 90 01 01 8b 5c 24 90 01 01 88 0c 1e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}