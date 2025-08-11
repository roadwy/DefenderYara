
rule Trojan_Win32_Obsidium_AB_MTB{
	meta:
		description = "Trojan:Win32/Obsidium.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 eb 03 36 03 51 33 c1 71 01 8f 33 d1 70 1b 89 45 f0 eb 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}