
rule Trojan_Win32_LummaStealer_JSM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.JSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 01 31 c8 35 5e fc 19 aa 89 44 24 04 8b 44 24 04 04 5a 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 89 c1 83 e1 01 89 c2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}