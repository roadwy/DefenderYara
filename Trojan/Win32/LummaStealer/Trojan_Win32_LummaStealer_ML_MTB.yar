
rule Trojan_Win32_LummaStealer_ML_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 f0 c7 45 90 02 05 83 45 f4 03 8b 45 ec c1 e0 04 83 3d 90 02 04 0c 89 45 fc 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}