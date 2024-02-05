
rule Trojan_Win32_TrickBot_DSP_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f be 0c 10 8b 55 f4 0f b6 82 90 01 04 33 c1 8b 4d f4 88 81 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}