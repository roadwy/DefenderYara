
rule Trojan_Win64_Emotet_RTA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {69 6c 61 68 6d 6e 70 6f 6b 70 6f 7a 6f 71 6c 7a 70 } //01 00  ilahmnpokpozoqlzp
		$a_81_1 = {68 67 72 63 6c 71 67 64 76 64 64 70 6a 68 } //01 00  hgrclqgdvddpjh
		$a_81_2 = {6e 6d 67 6f 68 77 6f 73 77 77 66 6d 77 61 6d } //01 00  nmgohwoswwfmwam
		$a_81_3 = {73 76 72 6d 75 6b 65 7a 75 6c 6e 74 67 61 76 61 } //00 00  svrmukezulntgava
	condition:
		any of ($a_*)
 
}