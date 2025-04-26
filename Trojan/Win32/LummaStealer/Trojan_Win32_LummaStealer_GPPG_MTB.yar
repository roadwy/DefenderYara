
rule Trojan_Win32_LummaStealer_GPPG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 80 c1 ?? 30 4c 04 02 40 83 f8 14 75 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}