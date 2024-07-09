
rule Trojan_Win32_Remcos_DM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0a 80 f3 ?? 88 19 83 c1 01 83 ed 01 75 ?? 66 8b 0d ?? ?? ?? ?? 66 3b 0d ?? ?? ?? ?? 5f 5e 5d 5b 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}