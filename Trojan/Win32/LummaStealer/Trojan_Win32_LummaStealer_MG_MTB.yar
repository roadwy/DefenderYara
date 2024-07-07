
rule Trojan_Win32_LummaStealer_MG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 34 01 4c 24 14 8b f3 c1 ee 05 8d 3c 2b 83 f8 1b 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}