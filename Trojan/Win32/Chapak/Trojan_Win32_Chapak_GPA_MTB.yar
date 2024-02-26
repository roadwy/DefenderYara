
rule Trojan_Win32_Chapak_GPA_MTB{
	meta:
		description = "Trojan:Win32/Chapak.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {31 75 fc 2b 7d fc 81 c3 90 01 04 ff 4d ec 89 7d f0 0f 85 fe fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}