
rule Trojan_Win32_Rugmi_RP_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 93 c1 39 c7 0f 93 c0 08 c1 0f 84 ?? ?? ?? ?? 8d 46 ff 83 f8 03 0f 86 ?? ?? ?? ?? 89 f1 66 0f 6e 54 24 0c 89 f8 c1 e9 02 c1 e1 04 66 0f 70 ca 00 01 f9 66 ?? f3 0f 6f 02 83 c0 ?? 83 c2 90 1b 03 66 0f fe c1 0f 11 40 f0 39 c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}