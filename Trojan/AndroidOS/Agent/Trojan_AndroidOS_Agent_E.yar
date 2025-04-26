
rule Trojan_AndroidOS_Agent_E{
	meta:
		description = "Trojan:AndroidOS/Agent.E,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 2f 63 6f 6d 2f 73 76 32 24 73 76 32 5f 42 52 3b } //10 g/com/sv2$sv2_BR;
		$a_00_1 = {43 61 6e 6e 6f 74 20 73 65 6e 64 20 66 69 6c 65 73 20 66 72 6f 6d 20 74 68 65 20 61 73 73 65 74 73 20 66 6f 6c 64 65 72 2e } //1 Cannot send files from the assets folder.
		$a_00_2 = {5f 70 6f 73 74 6d 75 6c 74 69 70 61 72 74 } //1 _postmultipart
		$a_00_3 = {2d 64 65 76 69 63 65 69 6e 66 6f 2e 74 78 74 } //1 -deviceinfo.txt
		$a_00_4 = {73 74 75 6e 2e 73 69 70 67 61 74 65 2e 6e 65 74 } //1 stun.sipgate.net
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=14
 
}