
rule Trojan_BAT_Watam_A{
	meta:
		description = "Trojan:BAT/Watam.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 00 77 00 69 00 74 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 78 00 62 00 69 00 6c 00 6c 00 79 00 62 00 6f 00 62 00 78 00 } //10 twitter.com/xbillybobx
		$a_01_1 = {57 00 54 00 46 00 20 00 49 00 53 00 20 00 54 00 48 00 49 00 53 00 3f 00 } //1 WTF IS THIS?
		$a_01_2 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 5c 00 73 00 6c 00 2e 00 6d 00 70 00 67 00 } //1 \svchost\sl.mpg
		$a_01_3 = {43 6f 6e 6e 65 63 74 54 6f 53 65 72 76 65 72 } //1 ConnectToServer
		$a_01_4 = {5c 00 73 00 69 00 6d 00 73 00 5c 00 55 00 73 00 65 00 72 00 44 00 61 00 74 00 61 00 } //1 \sims\UserData
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}