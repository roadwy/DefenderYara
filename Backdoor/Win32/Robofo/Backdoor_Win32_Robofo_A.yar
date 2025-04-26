
rule Backdoor_Win32_Robofo_A{
	meta:
		description = "Backdoor:Win32/Robofo.A,SIGNATURE_TYPE_PEHSTR,ffffffc6 02 ffffffc6 02 12 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5c 63 6f 6e 66 69 67 5c 53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66 } //100 \config\SteamAppData.vdf
		$a_01_2 = {32 30 33 2e 31 32 31 2e 37 39 2e 34 39 } //100 203.121.79.49
		$a_01_3 = {35 34 33 32 31 } //100 54321
		$a_01_4 = {52 6f 62 6f 46 6f 72 6d } //100 RoboForm
		$a_01_5 = {53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 73 73 6c } //100 System32\drivers\ssl
		$a_01_6 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4c 73 61 5c 64 69 73 61 62 6c 65 64 6f 6d 61 69 6e 63 72 65 64 73 } //100 SYSTEM\CurrentControlSet\Control\Lsa\disabledomaincreds
		$a_01_7 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 46 6f 78 5c } //2 \Mozilla\FireFox\
		$a_01_8 = {5c 4f 70 65 72 61 5c } //2 \Opera\
		$a_01_9 = {77 77 77 32 2e 73 63 61 73 64 2e 6f 72 67 } //2 www2.scasd.org
		$a_01_10 = {69 6e 2d 32 2d 77 65 62 32 2e 63 6f 6d } //2 in-2-web2.com
		$a_01_11 = {77 77 77 2e 68 75 71 75 71 61 6c 69 6e 73 61 6e 2e 63 6f 6d } //2 www.huquqalinsan.com
		$a_01_12 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 45 6e 61 62 6c 65 46 69 72 65 77 61 6c 6c } //2 SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall
		$a_01_13 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //1 http://www.google.com
		$a_01_14 = {68 6f 74 6d 61 69 6c } //1 hotmail
		$a_01_15 = {4c 6f 67 73 2f 50 61 73 73 } //1 Logs/Pass
		$a_01_16 = {2a 64 65 6c 66 69 6c 65 2a } //1 *delfile*
		$a_01_17 = {2a 65 78 65 63 75 74 65 2a } //1 *execute*
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*100+(#a_01_6  & 1)*100+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=710
 
}