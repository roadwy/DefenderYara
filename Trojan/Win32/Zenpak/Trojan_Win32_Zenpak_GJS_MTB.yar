
rule Trojan_Win32_Zenpak_GJS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b0 6c 88 44 24 90 01 01 88 44 24 90 01 01 88 44 24 90 01 01 8d 44 24 90 01 01 50 c6 44 24 90 01 01 56 c6 44 24 90 01 01 69 c6 44 24 90 01 01 72 c6 44 24 90 01 01 74 c6 44 24 90 01 01 75 c6 44 24 90 01 01 61 c6 44 24 90 01 01 41 c6 44 24 90 01 01 6f c6 44 24 90 01 01 63 c6 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}