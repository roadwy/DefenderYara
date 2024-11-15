
rule Trojan_Win32_SystemBC_CCJR_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 1f 33 45 f0 89 04 1e e8 ?? ?? ?? ?? 3b 45 e0 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}