
rule Trojan_iPhoneOS_Xagent_B_MTB{
	meta:
		description = "Trojan:iPhoneOS/Xagent.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 61 6c 6c 52 65 63 2e 64 79 6c 69 62 2e 62 61 39 36 34 63 39 30 2e 75 6e 73 69 67 6e 65 64 } //01 00  callRec.dylib.ba964c90.unsigned
		$a_00_1 = {2f 76 61 72 2f 74 72 61 73 74 4c 4f 67 2f 25 40 } //01 00  /var/trastLOg/%@
		$a_00_2 = {6d 69 63 2e 63 61 66 } //00 00  mic.caf
	condition:
		any of ($a_*)
 
}