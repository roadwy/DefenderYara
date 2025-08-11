
rule Trojan_Win32_Tofsee_BAI_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 40 fe 8d 40 01 29 d0 89 c2 c7 01 ?? ?? ?? ?? 31 01 83 e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}