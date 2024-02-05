
rule Trojan_Win32_Bunitu_DSP_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.DSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c9 33 3d 90 01 04 8b c9 90 00 } //01 00 
		$a_02_1 = {8b cf 8b d1 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}