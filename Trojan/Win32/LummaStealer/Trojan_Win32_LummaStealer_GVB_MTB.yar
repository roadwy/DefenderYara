
rule Trojan_Win32_LummaStealer_GVB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 cb 44 08 c8 34 01 08 d8 44 89 da 80 f2 01 45 30 c3 44 08 d2 } //2
		$a_02_1 = {0f 9c c2 0f 9c 45 ?? 89 d3 30 c3 20 d3 44 20 c9 20 c2 08 ca 89 d8 30 d0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}