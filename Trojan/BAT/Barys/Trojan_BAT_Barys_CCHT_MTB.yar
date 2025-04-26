
rule Trojan_BAT_Barys_CCHT_MTB{
	meta:
		description = "Trojan:BAT/Barys.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {3c 43 68 65 63 6b 41 56 3e } //1 <CheckAV>
		$a_01_1 = {3c 47 65 74 53 63 72 65 65 6e 73 68 6f 74 3e } //1 <GetScreenshot>
		$a_01_2 = {3c 47 65 74 43 6c 69 70 62 6f 61 72 64 3e } //1 <GetClipboard>
		$a_01_3 = {3c 67 65 74 5f 74 6f 6b 65 6e 73 3e } //1 <get_tokens>
		$a_01_4 = {3c 68 65 61 72 74 62 65 61 74 3e } //1 <heartbeat>
		$a_01_5 = {3c 53 68 65 6c 6c 43 6f 6d 6d 61 6e 64 3e } //1 <ShellCommand>
		$a_01_6 = {44 69 73 63 6f 72 64 5f 72 61 74 } //1 Discord_rat
		$a_01_7 = {72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 } //1 rootkit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}