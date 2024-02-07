
rule Backdoor_Win64_SignJoin_A{
	meta:
		description = "Backdoor:Win64/SignJoin.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 79 20 62 6f 6c 6c 73 20 2d 20 6d 79 20 72 75 6c 65 73 } //00 00  My bolls - my rules
	condition:
		any of ($a_*)
 
}