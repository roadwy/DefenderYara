
rule Trojan_Win32_LummaStealer_SLK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d1 83 f1 6a 01 f1 8b 75 ?? 29 f9 01 d1 32 0c 16 80 c1 ee 88 0c 16 42 83 fa 1c 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}