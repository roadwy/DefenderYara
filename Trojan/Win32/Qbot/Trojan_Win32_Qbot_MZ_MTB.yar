
rule Trojan_Win32_Qbot_MZ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff [0-04] 6a 00 89 [0-02] 29 ?? 31 ?? 89 ?? 5d 31 ?? 8b ?? ?? 83 ?? ?? aa 49 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}