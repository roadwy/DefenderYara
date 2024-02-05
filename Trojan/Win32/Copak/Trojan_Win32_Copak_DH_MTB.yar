
rule Trojan_Win32_Copak_DH_MTB{
	meta:
		description = "Trojan:Win32/Copak.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 03 81 c3 04 00 00 00 47 81 ef 25 b1 6a 9b 39 cb 75 } //01 00 
		$a_01_1 = {43 01 ff 29 c7 21 ff 81 fb 8f bc 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}