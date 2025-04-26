
rule Trojan_Win32_LummaStealer_CCFS_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce f7 e6 c1 ea ?? 6b c2 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 3b f7 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}