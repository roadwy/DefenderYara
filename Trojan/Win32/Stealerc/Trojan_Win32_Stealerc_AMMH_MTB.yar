
rule Trojan_Win32_Stealerc_AMMH_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 bc 24 90 01 04 0f 75 90 01 01 6a 00 6a 00 90 00 } //1
		$a_03_1 = {33 db 33 4d 90 02 14 33 c1 90 02 14 81 f9 13 02 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}