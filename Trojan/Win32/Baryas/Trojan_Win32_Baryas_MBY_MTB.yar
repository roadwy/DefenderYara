
rule Trojan_Win32_Baryas_MBY_MTB{
	meta:
		description = "Trojan:Win32/Baryas.MBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 5a 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 d0 57 40 00 c8 57 40 00 a8 14 40 00 78 00 00 00 7f 00 00 00 88 00 00 00 89 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}