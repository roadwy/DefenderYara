
rule DDoS_Linux_SAgnt_C_MTB{
	meta:
		description = "DDoS:Linux/SAgnt.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 63 72 6f 6e 74 61 62 20 2d 6c 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 3b 20 65 63 68 6f 20 22 40 72 65 62 6f 6f 74 20 25 73 22 29 20 7c 20 63 72 6f 6e 74 61 62 } //01 00  (crontab -l 2>/dev/null; echo "@reboot %s") | crontab
		$a_01_1 = {57 65 20 61 72 65 20 6b 69 6c 6c 69 6e 67 20 25 73 20 64 75 65 20 74 6f 20 69 74 20 68 61 76 69 6e 67 20 77 68 61 74 20 69 73 20 6d 6f 73 74 20 } //01 00  We are killing %s due to it having what is most 
		$a_01_2 = {6d 75 6c 74 69 2d 75 73 65 72 2e 74 61 72 67 65 74 } //00 00  multi-user.target
	condition:
		any of ($a_*)
 
}