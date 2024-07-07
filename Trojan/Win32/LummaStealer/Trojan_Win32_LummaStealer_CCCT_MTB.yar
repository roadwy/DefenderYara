
rule Trojan_Win32_LummaStealer_CCCT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 45 0c 30 54 07 90 01 01 8b 45 90 01 01 8b 10 8b 45 90 01 01 31 10 8b 54 9e 90 01 01 8b 45 90 01 01 03 d1 31 10 3b 7d 90 01 01 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}