
rule Trojan_Win32_Qakbot_SAN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f6 3a db 74 ?? bb ?? ?? ?? ?? 03 e3 bb ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 66 ?? ?? 74 } //1
		$a_00_1 = {57 69 6e 64 } //1 Wind
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}