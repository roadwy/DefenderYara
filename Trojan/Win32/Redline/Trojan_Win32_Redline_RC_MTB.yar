
rule Trojan_Win32_Redline_RC_MTB{
	meta:
		description = "Trojan:Win32/Redline.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 e4 50 6a 40 8b 0d 0c 30 41 00 51 68 ?? 14 40 00 ff 55 f8 89 45 e0 5f 5e 5b 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}