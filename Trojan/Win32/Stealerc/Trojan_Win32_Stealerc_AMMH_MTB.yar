
rule Trojan_Win32_Stealerc_AMMH_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 bc 24 ?? ?? ?? ?? 0f 75 ?? 6a 00 6a 00 } //1
		$a_03_1 = {33 db 33 4d [0-14] 33 c1 [0-14] 81 f9 13 02 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}