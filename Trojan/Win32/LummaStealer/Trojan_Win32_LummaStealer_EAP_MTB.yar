
rule Trojan_Win32_LummaStealer_EAP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.EAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 80 c1 95 32 4c 04 04 80 c1 d6 88 4c 04 04 89 c1 83 e1 01 83 f0 01 8d 04 48 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}