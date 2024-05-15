
rule Trojan_BAT_StealerC_EC_MTB{
	meta:
		description = "Trojan:BAT/StealerC.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 70 7a 2e 77 79 6a 73 71 2e 63 6e 2f 73 74 65 61 6d 73 70 65 65 64 41 45 53 70 7a 2e 62 69 6e } //01 00  http://pz.wyjsq.cn/steamspeedAESpz.bin
		$a_81_1 = {68 74 74 70 3a 2f 2f 70 7a 2e 77 79 6a 73 71 2e 63 6e 2f 67 78 72 7a 2e 74 78 74 } //01 00  http://pz.wyjsq.cn/gxrz.txt
		$a_81_2 = {6c 70 6b 6a 31 33 39 34 39 38 } //01 00  lpkj139498
		$a_81_3 = {3d 73 74 65 61 6d 73 74 6f 72 65 63 6f 6d 6d 75 6e 69 74 79 73 69 74 65 } //01 00  =steamstorecommunitysite
		$a_81_4 = {3d 73 74 65 61 6d 4c 69 76 65 76 69 64 65 6f 61 64 64 72 65 73 73 } //01 00  =steamLivevideoaddress
		$a_81_5 = {3d 73 74 65 61 6d 73 74 61 72 74 63 6c 69 65 6e 74 } //01 00  =steamstartclient
		$a_81_6 = {3d 73 74 65 61 6d 6f 74 68 65 72 73 69 74 65 } //01 00  =steamothersite
		$a_81_7 = {3d 67 69 74 68 75 62 73 69 74 65 } //01 00  =githubsite
		$a_81_8 = {3d 75 70 6c 61 79 73 69 74 65 } //01 00  =uplaysite
		$a_81_9 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //00 00  C:\Windows\System32\drivers\etc\hosts
	condition:
		any of ($a_*)
 
}