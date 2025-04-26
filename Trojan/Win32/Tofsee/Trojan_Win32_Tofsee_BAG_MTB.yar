
rule Trojan_Win32_Tofsee_BAG_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 54 24 12 8a 44 24 11 88 14 2e 80 e3 c0 08 5c 24 13 88 44 2e 01 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}