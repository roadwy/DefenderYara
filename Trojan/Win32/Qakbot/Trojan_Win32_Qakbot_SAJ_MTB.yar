
rule Trojan_Win32_Qakbot_SAJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 06 03 c2 25 ?? ?? ?? ?? 88 17 8b 55 ?? 8a 44 08 ?? 32 04 1a 88 03 43 ff 4d ?? 75 } //1
		$a_00_1 = {55 70 64 74 } //1 Updt
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}