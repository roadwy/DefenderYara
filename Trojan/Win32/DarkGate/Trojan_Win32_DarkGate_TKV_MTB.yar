
rule Trojan_Win32_DarkGate_TKV_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.TKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f3 8a 04 16 60 f2 0f 5c d4 f2 0f 10 e6 f2 0f 5c fa f2 0f 5c d4 f2 0f 2d c3 66 0f 59 d9 66 0f 14 c0 61 30 04 0f 41 89 c8 81 f9 07 80 17 00 76 cd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}