
rule Trojan_Win32_MaftaCorrupter_A{
	meta:
		description = "Trojan:Win32/MaftaCorrupter.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 64 00 20 00 63 00 3a 00 5c 00 3a 00 24 00 69 00 33 00 30 00 3a 00 24 00 62 00 69 00 74 00 6d 00 61 00 70 00 } //10 cd c:\:$i30:$bitmap
	condition:
		((#a_00_0  & 1)*10) >=10
 
}