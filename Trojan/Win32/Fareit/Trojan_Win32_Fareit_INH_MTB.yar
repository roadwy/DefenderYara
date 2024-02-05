
rule Trojan_Win32_Fareit_INH_MTB{
	meta:
		description = "Trojan:Win32/Fareit.INH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c b7 37 33 33 33 63 cc 65 3b 59 77 00 cc } //00 00 
	condition:
		any of ($a_*)
 
}