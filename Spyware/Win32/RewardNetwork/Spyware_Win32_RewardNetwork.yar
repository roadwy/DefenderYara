
rule Spyware_Win32_RewardNetwork{
	meta:
		description = "Spyware:Win32/RewardNetwork,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 57 65 62 47 75 69 64 65 } //1 SOFTWARE\WebGuide
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 41 70 70 44 61 74 61 4c 6f 77 } //1 SOFTWARE\AppDataLow
		$a_01_2 = {2e 77 65 62 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 } //1 .web-guide.co.kr
		$a_01_3 = {52 65 77 61 72 64 4e 65 74 77 6f 72 6b 2e } //1 RewardNetwork.
		$a_01_4 = {52 00 65 00 77 00 61 00 72 00 64 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 } //1 RewardNetwork.
		$a_01_5 = {44 00 61 00 74 00 61 00 77 00 61 00 76 00 65 00 } //1 Datawave
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Spyware_Win32_RewardNetwork_2{
	meta:
		description = "Spyware:Win32/RewardNetwork,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 57 65 62 47 75 69 64 65 } //1 SOFTWARE\WebGuide
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 41 70 70 44 61 74 61 4c 6f 77 } //1 SOFTWARE\AppDataLow
		$a_01_2 = {2e 77 65 62 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 } //1 .web-guide.co.kr
		$a_01_3 = {7b 44 46 33 30 31 45 42 41 2d 37 30 44 45 2d 33 37 36 44 2d 41 33 43 45 2d 38 37 37 34 32 39 43 39 44 37 30 33 7d } //1 {DF301EBA-70DE-376D-A3CE-877429C9D703}
		$a_01_4 = {57 65 62 2d 47 75 69 64 65 20 55 70 64 61 74 65 72 20 53 65 72 76 69 63 65 } //1 Web-Guide Updater Service
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Spyware_Win32_RewardNetwork_3{
	meta:
		description = "Spyware:Win32/RewardNetwork,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 52 65 77 61 72 64 4e 65 74 } //1 Software\RewardNet
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 41 70 70 44 61 74 61 4c 6f 77 } //1 SOFTWARE\AppDataLow
		$a_01_2 = {2e 72 65 77 61 72 64 6e 65 74 77 6f 72 6b 2e 6e 65 74 } //1 .rewardnetwork.net
		$a_01_3 = {52 65 77 61 72 64 4e 65 74 77 6f 72 6b 2e } //1 RewardNetwork.
		$a_01_4 = {52 00 65 00 77 00 61 00 72 00 64 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 } //1 RewardNetwork.
		$a_01_5 = {44 00 61 00 74 00 61 00 77 00 61 00 76 00 65 00 } //1 Datawave
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Spyware_Win32_RewardNetwork_4{
	meta:
		description = "Spyware:Win32/RewardNetwork,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 53 68 6f 70 47 75 69 64 65 5c } //1 SOFTWARE\ShopGuide\
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 41 70 70 44 61 74 61 4c 6f 77 } //1 SOFTWARE\AppDataLow
		$a_01_2 = {2e 73 68 6f 70 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 } //1 .shop-guide.co.kr
		$a_01_3 = {52 65 77 61 72 64 4e 65 74 77 6f 72 6b 2e } //1 RewardNetwork.
		$a_01_4 = {52 00 65 00 77 00 61 00 72 00 64 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 } //1 RewardNetwork.
		$a_01_5 = {44 00 61 00 74 00 61 00 77 00 61 00 76 00 65 00 } //1 Datawave
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Spyware_Win32_RewardNetwork_5{
	meta:
		description = "Spyware:Win32/RewardNetwork,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 63 72 69 70 74 2e 73 68 6f 70 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 73 63 72 69 70 74 2f 73 68 6f 70 67 75 69 64 65 2e 70 68 70 } //1 http://script.shop-guide.co.kr/script/shopguide.php
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 68 6f 70 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 63 73 2f 68 65 6c 70 2e 70 68 70 3f 74 79 70 65 3d 73 67 5f 6e 6f 74 69 63 65 } //1 http://www.shop-guide.co.kr/cs/help.php?type=sg_notice
		$a_01_2 = {68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e 73 68 6f 70 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 2f 75 70 64 61 74 65 2f } //1 http://update.shop-guide.co.kr/update/
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 53 68 6f 70 47 75 69 64 65 00 00 53 4f 46 54 57 41 52 45 5c 53 68 6f 70 47 75 69 64 65 5c 00 77 77 77 2e 73 68 6f 70 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 00 00 00 00 7b 30 30 30 30 30 30 30 30 2d 30 30 30 30 2d 30 30 30 30 2d 30 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 30 33 7d } //1
		$a_01_4 = {52 65 77 61 72 64 4e 65 74 77 6f 72 6b 2e 53 68 6f 70 47 75 69 64 65 2e 31 20 3d 20 73 20 27 52 65 77 61 72 64 4e 65 74 77 6f 72 6b 20 53 68 6f 70 47 75 69 64 65 20 43 6c 61 73 73 27 } //1 RewardNetwork.ShopGuide.1 = s 'RewardNetwork ShopGuide Class'
		$a_01_5 = {43 4c 53 49 44 20 3d 20 73 20 27 7b 33 43 42 30 43 46 34 32 2d 44 41 35 34 2d 34 37 64 32 2d 38 39 39 39 2d 32 33 39 32 38 41 32 44 45 41 34 32 7d 27 } //1 CLSID = s '{3CB0CF42-DA54-47d2-8999-23928A2DEA42}'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}