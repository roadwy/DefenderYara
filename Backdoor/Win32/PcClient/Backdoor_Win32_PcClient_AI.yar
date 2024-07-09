
rule Backdoor_Win32_PcClient_AI{
	meta:
		description = "Backdoor:Win32/PcClient.AI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 45 ec 50 0f b7 85 ?? ?? ff ff 50 8b 45 08 (83 c0 ?? 05 ??|?? 00 00 50 ff b5) ?? ?? ff ff ff 15 ?? ?? 40 00 0f b7 85 ?? ?? ff ff 50 8b 45 08 90 03 05 06 83 c0 ?? 05 ?? ?? 00 00 50 e8 ?? ?? 00 00 59 59 6a 00 8d 45 ec 50 } //1
		$a_03_1 = {99 6a 1a 59 f7 f9 8b 45 08 03 85 ?? ?? ff ff 88 90 90 78 02 00 00 8b 45 08 03 85 ?? ?? ff ff 8a 80 78 02 00 00 ?? ?? 8b 4d 08 03 8d ?? ?? ff ff 88 81 78 02 00 00 eb ad } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}