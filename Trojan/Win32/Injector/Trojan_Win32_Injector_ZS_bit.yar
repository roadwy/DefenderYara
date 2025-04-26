
rule Trojan_Win32_Injector_ZS_bit{
	meta:
		description = "Trojan:Win32/Injector.ZS!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {23 37 83 c7 ?? f7 d6 f8 83 de ?? c1 ce ?? d1 c6 01 c6 8d 76 ff 29 c0 29 f0 f7 d8 c1 c0 ?? d1 c8 56 8f 03 83 c3 04 83 c2 fc 85 d2 75 d0 } //1
		$a_00_1 = {5b 8b 15 50 70 46 00 52 ff d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}