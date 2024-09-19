
rule Trojan_Win32_LummaStealer_CCIY_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 02 8b 8d ?? f8 ff ff 8b 11 83 c2 01 33 c2 8b 8d ?? f8 ff ff c1 e1 00 03 8d ?? f8 ff ff 88 01 eb ?? 8b 95 ?? f8 ff ff 8b 02 83 c0 02 8b 8d ?? f8 ff ff 39 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}