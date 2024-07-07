
rule Trojan_Win32_Symmi_CCAP_MTB{
	meta:
		description = "Trojan:Win32/Symmi.CCAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8a 88 88 58 5d 00 88 4d ef 0f b6 45 ef 83 f0 90 01 01 88 45 ef 0f b6 45 ef f7 d8 88 45 ef 0f b6 45 ef 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}