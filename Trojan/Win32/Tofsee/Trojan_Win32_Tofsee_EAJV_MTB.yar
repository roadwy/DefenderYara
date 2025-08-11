
rule Trojan_Win32_Tofsee_EAJV_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8a 84 37 3b 2d 0b 00 5f 88 04 31 5e 8b e5 5d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}