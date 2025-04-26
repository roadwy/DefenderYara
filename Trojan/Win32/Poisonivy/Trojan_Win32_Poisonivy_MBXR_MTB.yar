
rule Trojan_Win32_Poisonivy_MBXR_MTB{
	meta:
		description = "Trojan:Win32/Poisonivy.MBXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b0 25 40 00 78 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 0c 11 40 00 0c 11 40 00 d0 10 40 00 78 00 00 00 80 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}