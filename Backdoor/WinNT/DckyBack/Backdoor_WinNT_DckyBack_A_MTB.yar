
rule Backdoor_WinNT_DckyBack_A_MTB{
	meta:
		description = "Backdoor:WinNT/DckyBack.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 68 61 74 63 68 65 72 63 6c 6f 75 67 68 2f 62 65 74 74 65 72 62 61 63 6b 64 6f 6f 72 2f 73 68 65 6c 6c 2f 48 61 6e 64 6c 65 43 6f 6d 6d 61 6e 64 } //1 thatcherclough/betterbackdoor/shell/HandleCommand
		$a_00_1 = {44 75 63 6b 79 53 63 72 69 70 74 } //1 DuckyScript
		$a_00_2 = {5c 6b 65 79 73 2e 6c 6f 67 } //1 \keys.log
		$a_00_3 = {45 6e 74 65 72 20 76 69 63 74 69 6d 27 73 20 66 69 6c 65 70 61 74 68 20 6f 66 20 66 69 6c 65 20 74 6f 20 73 65 6e 64 } //1 Enter victim's filepath of file to send
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}