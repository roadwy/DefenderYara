
rule Trojan_Win32_Bunitu_PVJ_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 8d 94 01 ?? ?? ?? ?? 89 55 ec 8b 45 ec a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d fc 83 c1 04 89 4d fc ba bd 01 00 00 85 d2 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}