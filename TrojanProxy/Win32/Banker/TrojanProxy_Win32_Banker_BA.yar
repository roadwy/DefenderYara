
rule TrojanProxy_Win32_Banker_BA{
	meta:
		description = "TrojanProxy:Win32/Banker.BA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_02_0 = {69 6e 74 65 72 6e 65 74 2d 6f 70 74 69 6f 6e 73 2e 63 6f 6d 2e 62 72 2f 69 65 [0-10] 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c } //10
		$a_00_1 = {5c 41 38 37 41 53 33 48 49 55 34 2e 74 78 74 } //1 \A87AS3HIU4.txt
		$a_00_2 = {32 31 36 2e 32 34 35 2e 31 39 39 2e 31 39 35 2f 69 6e 64 65 78 2e 70 68 70 } //1 216.245.199.195/index.php
		$a_00_3 = {5c 48 41 55 45 48 45 46 55 48 46 55 45 41 4e 2e 74 78 74 } //1 \HAUEHEFUHFUEAN.txt
		$a_00_4 = {68 74 74 70 3a 2f 2f 73 69 73 68 61 62 2e 75 68 6f 73 74 69 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 } //1 http://sishab.uhosti.com/index.php
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=12
 
}