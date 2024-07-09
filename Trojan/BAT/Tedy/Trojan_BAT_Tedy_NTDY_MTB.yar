
rule Trojan_BAT_Tedy_NTDY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NTDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 09 9a 07 09 9a 6f ?? 00 00 0a 00 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } //5
		$a_01_1 = {46 00 69 00 6c 00 65 00 73 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 73 00 65 00 74 00 20 00 74 00 6f 00 20 00 72 00 75 00 6e 00 20 00 61 00 74 00 20 00 75 00 73 00 65 00 72 00 20 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 } //1 Files downloaded and set to run at user startup
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}