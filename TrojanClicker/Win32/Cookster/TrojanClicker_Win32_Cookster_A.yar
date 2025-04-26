
rule TrojanClicker_Win32_Cookster_A{
	meta:
		description = "TrojanClicker:Win32/Cookster.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 30 e8 ?? ?? ff ff 6a 0f 6a 03 89 44 24 4c e8 ?? ?? ff ff 6a 64 6a 28 89 44 24 50 e8 ?? ?? ff ff 6a 0f 6a 03 89 44 24 54 e8 ?? ?? ff ff } //2
		$a_01_1 = {25 73 26 63 6b 3d 25 64 2e 25 64 2e 25 64 2e 25 64 2e 25 64 2e 25 64 2e 25 64 2e 25 64 } //1 %s&ck=%d.%d.%d.%d.%d.%d.%d.%d
		$a_01_2 = {42 44 28 27 25 73 27 29 2e 53 65 61 72 63 68 41 6e 64 43 6c 69 63 6b 28 27 25 73 27 29 3b } //1 BD('%s').SearchAndClick('%s');
		$a_01_3 = {2f 73 65 6e 74 72 79 2f 61 70 69 2f 73 65 72 76 65 72 2e 70 68 70 } //1 /sentry/api/server.php
		$a_01_4 = {74 72 61 66 66 69 63 2e 67 65 74 41 63 74 69 6f 6e 4c 69 73 74 46 72 6f 6d 48 54 4d 4c } //1 traffic.getActionListFromHTML
		$a_01_5 = {42 72 6f 77 73 65 72 28 29 2e 49 6e 76 6f 6b 65 53 63 72 69 70 74 28 27 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 27 25 73 27 29 2e 6f 6e 6d 6f 75 73 65 64 6f 77 6e 28 29 3b 27 29 3b } //1 Browser().InvokeScript('document.getElementById('%s').onmousedown();');
		$a_01_6 = {42 72 6f 77 73 65 72 28 29 2e 49 6e 76 6f 6b 65 53 63 72 69 70 74 28 27 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 27 25 73 27 29 2e 63 6c 69 63 6b 28 29 3b 27 29 3b } //1 Browser().InvokeScript('document.getElementById('%s').click();');
		$a_01_7 = {43 6c 69 65 6e 74 28 29 2e 53 6c 65 65 70 28 27 35 27 29 3b } //1 Client().Sleep('5');
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}