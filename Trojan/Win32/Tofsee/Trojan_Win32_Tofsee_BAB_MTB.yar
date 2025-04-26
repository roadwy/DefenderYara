
rule Trojan_Win32_Tofsee_BAB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 89 c2 c7 46 ?? ?? ?? ?? ?? 31 06 8d 76 04 8d 49 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}