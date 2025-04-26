
rule Trojan_Win32_Tofsee_EAKH_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 ac 24 ac 01 00 00 68 6c 98 55 8a 84 37 3b 2d 0b 00 88 04 0e 46 3b 35 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}