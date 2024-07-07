
rule Trojan_Win32_LummaStealer_CCCP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 17 8b 3c 24 6b da 90 01 01 8d bc 3b 90 01 04 89 3c 24 31 d0 89 c2 0f af 14 24 6b d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}