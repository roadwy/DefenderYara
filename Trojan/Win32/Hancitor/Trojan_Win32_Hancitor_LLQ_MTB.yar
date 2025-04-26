
rule Trojan_Win32_Hancitor_LLQ_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.LLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 39 0f b7 ca 89 4c 24 [0-02] 8b 4c 24 [0-02] 8d 04 41 8b 4c 24 [0-02] 81 c1 ?? ?? ?? ?? 03 c8 83 3d ?? ?? ?? ?? ?? 74 ?? 0f af 0d ?? ?? ?? ?? 2b 4c 24 ?? 90 18 83 c1 1e 0f b7 c2 2b c6 81 c7 cc 4a 06 01 03 c1 89 3d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}