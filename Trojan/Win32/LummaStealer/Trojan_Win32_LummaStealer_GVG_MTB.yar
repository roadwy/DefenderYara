
rule Trojan_Win32_LummaStealer_GVG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 33 ff 33 c9 89 7d 08 8b c1 83 e0 03 8a 44 05 08 30 04 0a 41 3b ce } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}