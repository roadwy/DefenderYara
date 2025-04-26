
rule Trojan_Win32_Buthz_A{
	meta:
		description = "Trojan:Win32/Buthz.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 29 f6 01 c6 56 83 fb 00 74 37 6a ff 58 23 01 83 e9 fc 83 c0 cd c1 c8 08 29 f8 83 e8 01 31 ff 29 c7 f7 df c1 c7 09 d1 cf 6a 00 8f 06 01 06 8d 76 04 83 eb 04 [0-06] 05 87 d6 12 00 50 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}