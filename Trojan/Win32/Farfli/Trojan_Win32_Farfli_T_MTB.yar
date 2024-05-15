
rule Trojan_Win32_Farfli_T_MTB{
	meta:
		description = "Trojan:Win32/Farfli.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {3a f7 af 53 43 82 e2 90 01 01 27 ce 53 80 43 90 00 } //02 00 
		$a_01_1 = {8d 3b fa ed 28 20 c9 27 96 11 98 } //00 00 
	condition:
		any of ($a_*)
 
}