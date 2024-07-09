
rule Trojan_Win32_Qakbot_SD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 48 3c 81 f7 ?? ?? ?? ?? 0f af fb 8d 41 ?? f7 d0 03 fa 8b 52 ?? 4a 03 d1 85 d0 } //1
		$a_03_1 = {33 cb 42 89 4e ?? 69 85 ?? ?? ?? ?? ?? ?? ?? ?? 3b d0 76 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}