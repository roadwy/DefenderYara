
rule Trojan_Win32_LummaStealer_MFF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 48 00 00 00 29 c2 05 b7 25 94 b0 31 c2 21 ca 31 c2 89 54 24 04 8b 44 24 04 fe c8 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8 20 72 c7 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}