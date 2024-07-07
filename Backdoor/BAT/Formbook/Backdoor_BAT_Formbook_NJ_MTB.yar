
rule Backdoor_BAT_Formbook_NJ_MTB{
	meta:
		description = "Backdoor:BAT/Formbook.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 35 01 00 00 23 01 00 00 ad 04 00 00 df 0e 00 00 57 09 00 00 35 00 00 00 9f 03 00 00 1c 00 00 00 3b 00 00 00 08 00 00 00 01 00 00 00 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}