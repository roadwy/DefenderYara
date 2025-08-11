
rule Trojan_Win32_Tofsee_EAZU_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.EAZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b b4 24 a0 02 00 00 8a 84 37 3b 2d 0b 00 5f 88 04 31 5e 81 c4 94 02 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}