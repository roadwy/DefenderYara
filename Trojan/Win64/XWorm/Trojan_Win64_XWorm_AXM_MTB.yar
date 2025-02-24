
rule Trojan_Win64_XWorm_AXM_MTB{
	meta:
		description = "Trojan:Win64/XWorm.AXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 45 70 69 63 47 61 6d 65 73 4c 61 75 6e 63 68 65 72 2e 65 78 65 20 2f 46 } //2 taskkill /IM EpicGamesLauncher.exe /F
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 46 6f 72 74 6e 69 74 65 43 6c 69 65 6e 74 2d 57 69 6e 36 34 2d 53 68 69 70 70 69 6e 67 5f 42 45 2e 65 78 65 20 2f 46 } //2 taskkill /IM FortniteClient-Win64-Shipping_BE.exe /F
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 46 6f 72 74 6e 69 74 65 43 6c 69 65 6e 74 2d 57 69 6e 36 34 2d 53 68 69 70 70 69 6e 67 2e 65 78 65 20 2f 46 } //2 taskkill /IM FortniteClient-Win64-Shipping.exe /F
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 78 36 34 64 62 67 2e 65 78 65 } //2 taskkill /IM x64dbg.exe
		$a_01_4 = {6e 65 74 20 73 74 6f 70 20 77 69 6e 6d 67 6d 74 } //3 net stop winmgmt
		$a_01_5 = {69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 65 74 73 68 20 77 69 6e 73 6f 63 6b 20 72 65 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6e 65 74 73 68 20 69 6e 74 20 69 70 76 34 20 72 6e 65 74 73 68 20 69 6e 74 20 69 70 76 36 20 72 69 70 63 6f 6e 66 69 67 20 2f 72 65 6c 65 61 73 6e 65 74 73 68 20 69 6e 74 20 69 70 20 72 65 73 } //4 ipconfig /flushdnetsh winsock renetsh advfirewalnetsh int ipv4 rnetsh int ipv6 ripconfig /releasnetsh int ip res
		$a_01_6 = {50 65 72 6d 61 6e 65 6e 74 20 53 70 6f 6f 66 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 65 72 6d 61 6e 65 6e 74 20 53 70 6f 6f 66 65 72 2e 70 64 62 } //5 Permanent Spoofer\x64\Release\Permanent Spoofer.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3+(#a_01_5  & 1)*4+(#a_01_6  & 1)*5) >=20
 
}