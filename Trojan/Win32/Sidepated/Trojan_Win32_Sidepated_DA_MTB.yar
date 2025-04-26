
rule Trojan_Win32_Sidepated_DA_MTB{
	meta:
		description = "Trojan:Win32/Sidepated.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1a 33 d2 32 87 ?? ?? ?? ?? 88 01 8d 47 01 f7 f6 0f b6 04 1a 32 87 ?? ?? ?? ?? 83 c7 04 88 41 01 8b 4c 24 0c 83 c1 04 89 4c 24 0c 81 ff 02 20 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}