
rule Trojan_Win32_LummaStealer_RJP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 89 c6 68 f0 fc 54 a1 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}