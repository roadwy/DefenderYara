
rule Trojan_BAT_Tedy_NTD_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0a 6f 2d 00 00 0a 11 15 16 11 13 6f 90 01 01 00 00 0a 13 14 11 16 11 15 16 11 14 6f 90 01 01 00 00 0a 00 00 11 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 1a 11 1a 2d cc 90 00 } //5
		$a_01_1 = {7a 00 30 00 46 00 53 00 41 00 6d 00 6d 00 7a 00 } //1 z0FSAmmz
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}