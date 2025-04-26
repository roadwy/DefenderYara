
rule Trojan_Win32_Remcos_ARC_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 10 85 d2 76 15 55 a1 ?? ?? ?? ?? 03 f2 50 56 57 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}