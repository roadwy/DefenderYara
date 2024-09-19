
rule Trojan_Win32_Pterdo_YAI_MTB{
	meta:
		description = "Trojan:Win32/Pterdo.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 8b 4d ec 03 4d e0 0f b6 51 ff 33 c2 8b 4d ec 03 4d e0 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}