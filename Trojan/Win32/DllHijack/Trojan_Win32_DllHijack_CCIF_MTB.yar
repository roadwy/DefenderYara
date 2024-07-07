
rule Trojan_Win32_DllHijack_CCIF_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.CCIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 31 47 32 d0 8b c1 88 14 31 99 f7 fb 85 d2 75 90 01 01 33 ff 8b 44 24 90 01 01 41 3b c8 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}