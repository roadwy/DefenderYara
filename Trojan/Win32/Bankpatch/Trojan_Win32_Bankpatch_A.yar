
rule Trojan_Win32_Bankpatch_A{
	meta:
		description = "Trojan:Win32/Bankpatch.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 08 8b 40 04 e8 00 00 00 00 5a 8d 92 90 03 01 01 20 21 00 00 00 33 c9 90 02 02 39 02 74 0c 83 c2 04 39 0a 75 f5 e9 90 01 04 33 c0 48 c2 0c 00 d8 8f 46 4b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}