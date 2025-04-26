
rule Trojan_Win32_LummaStealer_MML_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {54 03 c3 2e 82 a7 a7 a7 a7 4c 96 8d 05 02 20 40 00 80 30 a7 40 3d 34 20 40 00 75 ?? 05 54 82 37 1c 29 c0 29 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}