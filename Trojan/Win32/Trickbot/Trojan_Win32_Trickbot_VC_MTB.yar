
rule Trojan_Win32_Trickbot_VC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 15 ?? ?? ?? ?? 0f b6 c3 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4e ?? 8b 8d ?? ?? ?? ?? 4f } //1
		$a_03_1 = {8a 1c 38 30 19 03 ce 03 fe 90 13 3b ca 90 13 83 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}