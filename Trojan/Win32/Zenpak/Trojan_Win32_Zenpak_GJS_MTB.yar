
rule Trojan_Win32_Zenpak_GJS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b0 6c 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? 50 c6 44 24 ?? 56 c6 44 24 ?? 69 c6 44 24 ?? 72 c6 44 24 ?? 74 c6 44 24 ?? 75 c6 44 24 ?? 61 c6 44 24 ?? 41 c6 44 24 ?? 6f c6 44 24 ?? 63 c6 44 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}