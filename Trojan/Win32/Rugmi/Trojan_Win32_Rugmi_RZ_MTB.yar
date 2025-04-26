
rule Trojan_Win32_Rugmi_RZ_MTB{
	meta:
		description = "Trojan:Win32/Rugmi.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 05 00 03 ca 89 0c 06 8b 4b ?? 03 c1 8b 4b ?? 3b c1 72 eb } //2
		$a_03_1 = {8b 43 28 8b 0c 30 89 0c 32 8b 7b ?? 03 f7 8b 43 ?? 3b f0 72 eb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}