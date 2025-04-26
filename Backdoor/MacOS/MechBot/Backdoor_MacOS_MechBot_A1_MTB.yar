
rule Backdoor_MacOS_MechBot_A1_MTB{
	meta:
		description = "Backdoor:MacOS/MechBot.A1!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 2f 6d 65 63 68 2e 68 65 6c 70 } //1 ./mech.help
		$a_00_1 = {30 21 70 69 70 65 40 65 6e 65 72 67 79 6d 65 63 68 } //1 0!pipe@energymech
		$a_00_2 = {73 21 73 68 65 6c 6c 40 65 6e 65 72 67 79 6d 65 63 68 } //1 s!shell@energymech
		$a_00_3 = {2e 2f 72 61 6e 64 66 69 6c 65 73 2f 72 61 6e 64 73 69 67 6e 6f 66 66 2e 65 } //1 ./randfiles/randsignoff.e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}