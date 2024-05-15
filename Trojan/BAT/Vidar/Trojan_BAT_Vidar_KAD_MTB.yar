
rule Trojan_BAT_Vidar_KAD_MTB{
	meta:
		description = "Trojan:BAT/Vidar.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 20 00 01 00 00 5d 90 02 1e 61 d2 52 90 00 } //01 00 
		$a_01_1 = {4d 53 47 5f 4e 45 54 } //01 00  MSG_NET
		$a_01_2 = {41 6e 67 65 6c 6f } //00 00  Angelo
	condition:
		any of ($a_*)
 
}