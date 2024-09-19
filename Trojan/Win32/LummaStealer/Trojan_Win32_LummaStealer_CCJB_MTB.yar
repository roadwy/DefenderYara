
rule Trojan_Win32_LummaStealer_CCJB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 14 10 81 c1 ?? ?? ?? ?? 31 d1 89 4c 24 08 8b 4c 24 08 89 ca 83 ca 45 83 e1 45 01 d1 fe c1 8b 54 24 04 88 4c 14 10 ff 44 24 04 8b 4c 24 04 83 f9 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}