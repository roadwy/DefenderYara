
rule Trojan_Win32_LummaStealer_PB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c6 83 e6 08 89 ca 83 f2 64 01 f2 32 54 0c ?? 80 c2 38 88 54 0c ?? 41 83 c0 02 83 f9 14 75 ?? 8d 44 24 ?? 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}