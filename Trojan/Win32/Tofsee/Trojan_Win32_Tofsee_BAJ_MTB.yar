
rule Trojan_Win32_Tofsee_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 29 d8 50 5b 6a 00 8f 02 01 42 00 83 c2 04 8d 49 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}