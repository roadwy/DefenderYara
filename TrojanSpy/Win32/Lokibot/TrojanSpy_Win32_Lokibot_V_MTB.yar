
rule TrojanSpy_Win32_Lokibot_V_MTB{
	meta:
		description = "TrojanSpy:Win32/Lokibot.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b3 02 33 ff [0-06] 8b c7 [0-05] 8a 90 90 ?? ?? ?? ?? 32 d3 [0-05] a1 ?? ?? ?? ?? 03 c7 [0-04] 8b f0 [0-06] 8b c6 e8 ?? ?? ?? ?? [0-05] 47 81 ff ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}