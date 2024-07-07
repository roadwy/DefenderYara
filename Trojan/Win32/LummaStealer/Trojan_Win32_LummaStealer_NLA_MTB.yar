
rule Trojan_Win32_LummaStealer_NLA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 d5 f6 c2 01 8b 7c 24 90 01 01 74 20 89 c2 81 f2 fe ff ff 3f 90 00 } //3
		$a_03_1 = {c9 89 8c 84 90 01 04 83 bc 24 c8 15 00 00 90 01 01 0f 8e c0 00 00 00 31 c0 8b 4c 24 90 01 01 8d 0c c9 89 ca 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}