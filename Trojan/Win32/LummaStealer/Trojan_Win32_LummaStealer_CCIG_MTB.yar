
rule Trojan_Win32_LummaStealer_CCIG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 28 8b 6c 24 ?? a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 90 90 90 90 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}