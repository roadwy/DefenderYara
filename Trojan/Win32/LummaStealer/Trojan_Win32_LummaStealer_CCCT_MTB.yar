
rule Trojan_Win32_LummaStealer_CCCT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 45 0c 30 54 07 ?? 8b 45 ?? 8b 10 8b 45 ?? 31 10 8b 54 9e ?? 8b 45 ?? 03 d1 31 10 3b 7d ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}