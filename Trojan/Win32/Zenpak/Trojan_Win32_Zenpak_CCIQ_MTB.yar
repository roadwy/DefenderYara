
rule Trojan_Win32_Zenpak_CCIQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 48 01 c2 83 f0 07 8d 05 ?? ?? ?? ?? 89 20 eb 1a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}