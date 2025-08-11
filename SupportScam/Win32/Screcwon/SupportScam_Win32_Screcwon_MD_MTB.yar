
rule SupportScam_Win32_Screcwon_MD_MTB{
	meta:
		description = "SupportScam:Win32/Screcwon.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0a 00 00 "
		
	strings :
		$a_81_0 = {52 65 6c 65 61 73 65 5c 43 6c 69 63 6b 4f 6e 63 65 52 75 6e 6e 65 72 2e 70 64 62 } //20 Release\ClickOnceRunner.pdb
		$a_81_1 = {52 65 6c 65 61 73 65 5c 44 6f 74 4e 65 74 52 75 6e 6e 65 72 2e 70 64 62 } //20 Release\DotNetRunner.pdb
		$a_81_2 = {2e 66 69 6c 65 73 64 6f 6e 77 6c 6f 61 64 73 2e 63 6f 6d } //30 .filesdonwloads.com
		$a_81_3 = {72 65 6c 61 79 2e 6d 61 67 61 72 65 74 63 61 70 2e 63 6f 6d } //30 relay.magaretcap.com
		$a_81_4 = {72 65 6c 61 79 2e 73 68 69 70 70 65 72 7a 6f 6e 65 2e 6f 6e 6c 69 6e 65 } //30 relay.shipperzone.online
		$a_81_5 = {66 6d 74 32 61 73 2e 64 64 6e 73 2e 6e 65 74 } //30 fmt2as.ddns.net
		$a_81_6 = {61 70 70 2e 72 61 74 6f 73 63 72 65 65 6e 73 65 6c 6c 2e 63 6f 6d } //30 app.ratoscreensell.com
		$a_81_7 = {72 65 6c 61 79 2e 61 6c 65 33 72 74 2e 69 6e } //30 relay.ale3rt.in
		$a_81_8 = {6d 69 63 72 6f 73 6f 66 66 65 65 64 64 34 61 63 6b 61 70 69 7a 2e 65 6e 74 65 72 70 72 69 73 65 73 6f 6c 75 74 69 6f 6e 73 2e 73 75 } //30 microsoffeedd4ackapiz.enterprisesolutions.su
		$a_81_9 = {2e 70 75 74 69 6e 73 77 69 6e 2e 65 73 } //30 .putinswin.es
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*30+(#a_81_3  & 1)*30+(#a_81_4  & 1)*30+(#a_81_5  & 1)*30+(#a_81_6  & 1)*30+(#a_81_7  & 1)*30+(#a_81_8  & 1)*30+(#a_81_9  & 1)*30) >=50
 
}