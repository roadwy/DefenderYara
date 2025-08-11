
rule Trojan_Win32_Neoreblamy_HB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.HB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 [0-06] 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 90 22 10 03 61 2d 7a 5c 00 90 22 07 03 61 2d 7a 2e 00 77 00 73 00 66 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}