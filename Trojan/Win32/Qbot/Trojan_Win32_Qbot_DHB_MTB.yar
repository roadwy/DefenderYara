
rule Trojan_Win32_Qbot_DHB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {01 d8 89 54 24 ?? 99 f7 fe 88 c8 8a 4c 24 ?? f6 e1 88 44 24 } //1
		$a_02_1 = {01 d8 25 ff 00 00 00 2a 4c 24 ?? 88 4c 24 ?? 8b 5c 24 ?? 32 2c 03 8b 44 24 ?? 88 2c 10 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}