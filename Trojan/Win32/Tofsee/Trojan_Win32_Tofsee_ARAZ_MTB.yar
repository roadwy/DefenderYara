
rule Trojan_Win32_Tofsee_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 2b fe 8b 44 24 70 29 44 24 0c 83 6c 24 60 01 0f 85 53 fb ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}