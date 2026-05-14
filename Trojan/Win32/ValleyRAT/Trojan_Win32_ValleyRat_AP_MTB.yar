
rule Trojan_Win32_ValleyRat_AP_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f8 83 e0 0f 30 ca 80 c1 07 32 90 12 6c 42 00 89 f8 47 83 e0 1f 32 90 f2 6b 42 00 8b 46 08 88 14 18 43 81 ff ca 09 00 00 75 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}