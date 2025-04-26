
rule Backdoor_BAT_MessChange_B_dha{
	meta:
		description = "Backdoor:BAT/MessChange.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4d 00 53 00 45 00 78 00 63 00 68 00 61 00 6e 00 67 00 65 00 42 00 61 00 63 00 6b 00 65 00 6e 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}