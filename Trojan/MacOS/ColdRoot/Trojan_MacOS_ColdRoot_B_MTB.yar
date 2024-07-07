
rule Trojan_MacOS_ColdRoot_B_MTB{
	meta:
		description = "Trojan:MacOS/ColdRoot.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {48 5f 52 65 6d 6f 74 65 44 65 73 6b 74 6f 70 20 52 65 71 75 65 73 74 65 64 20 2e 2e } //H_RemoteDesktop Requested ..  1
		$a_01_1 = {2f 70 72 69 76 61 74 65 2f 76 61 72 2f 74 6d 70 2f 72 75 6e 6d 65 2e 73 68 } //1 /private/var/tmp/runme.sh
		$a_80_2 = {43 4f 4c 44 5a 45 52 30 5f 4f 4b } //COLDZER0_OK  1
		$a_80_3 = {43 6f 64 65 64 20 42 79 20 43 6f 6c 64 7a 65 72 30 20 2f 20 53 6b 79 70 65 3a 43 6f 6c 64 7a 65 72 30 31 } //Coded By Coldzer0 / Skype:Coldzer01  1
		$a_02_4 = {c6 40 38 01 8d 83 2f d1 1b 00 e8 90 01 04 eb 15 8b 83 83 22 1e 00 c6 40 38 00 8d 83 5b d1 1b 00 e8 90 01 04 8d 83 83 d1 1b 00 e8 90 01 04 8b 83 83 22 1e 00 83 78 48 00 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*1) >=3
 
}