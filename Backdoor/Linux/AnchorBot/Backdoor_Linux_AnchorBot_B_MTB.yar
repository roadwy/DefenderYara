
rule Backdoor_Linux_AnchorBot_B_MTB{
	meta:
		description = "Backdoor:Linux/AnchorBot.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 61 6e 63 68 6f 72 2e 6c 6f 67 } //02 00  /tmp/anchor.log
		$a_00_1 = {69 63 61 6e 68 61 7a 69 70 2e 63 6f 6d } //01 00  icanhazip.com
		$a_00_2 = {66 74 70 3a 2f 2f 25 73 3a 25 73 40 25 73 } //01 00  ftp://%s:%s@%s
		$a_00_3 = {73 6d 62 32 5f 77 72 69 74 65 5f 61 73 79 6e 63 } //00 00  smb2_write_async
	condition:
		any of ($a_*)
 
}