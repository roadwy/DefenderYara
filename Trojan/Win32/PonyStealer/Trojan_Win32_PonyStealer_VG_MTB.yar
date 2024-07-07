
rule Trojan_Win32_PonyStealer_VG_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.VG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 f7 c1 d7 0b 31 34 24 f7 c2 0a 17 ce b5 81 fb 6b 19 ce b5 81 f9 cc 1b ce b5 81 fa bc 1d ce b5 66 81 fa 08 20 8f 04 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}