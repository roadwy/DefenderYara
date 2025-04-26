
rule TrojanSpy_Win32_Noon_KH_MTB{
	meta:
		description = "TrojanSpy:Win32/Noon.KH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 33 c9 89 bd ?? ?? ?? ?? 85 db 74 1b 8d 49 ?? 8a 81 ?? ?? ?? ?? 30 04 3a 83 f9 ?? ?? ?? 33 c9 ?? ?? 41 42 3b d3 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}