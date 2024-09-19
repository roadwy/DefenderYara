
rule Trojan_Win32_LummaStealer_MWW_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d9 80 e1 10 d3 e5 89 fa 83 e2 fc 33 6c 14 1c 89 6c 14 ?? 0f b6 74 38 01 80 c9 08 d3 e6 31 ee 89 74 14 ?? 83 c7 02 83 c3 10 39 3c 24 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}