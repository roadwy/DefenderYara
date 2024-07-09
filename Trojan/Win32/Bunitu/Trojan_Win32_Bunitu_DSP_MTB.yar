
rule Trojan_Win32_Bunitu_DSP_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.DSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c9 33 3d ?? ?? ?? ?? 8b c9 } //1
		$a_02_1 = {8b cf 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}