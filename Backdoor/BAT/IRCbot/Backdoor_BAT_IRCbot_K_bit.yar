
rule Backdoor_BAT_IRCbot_K_bit{
	meta:
		description = "Backdoor:BAT/IRCbot.K!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 6c 00 54 00 65 00 6e 00 4d 00 61 00 74 00 2e 00 56 00 42 00 53 00 } //1 \DelTenMat.VBS
		$a_01_1 = {63 74 66 6d 6f 6e 2e 65 78 65 00 00 72 73 6d 61 69 6e 2e 65 78 65 00 00 33 36 30 54 72 61 79 2e 65 78 65 00 54 65 6e 49 6e 66 65 63 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}