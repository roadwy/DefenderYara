
rule Trojan_Win64_StrelaStealer_GTT_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 [0-01] ff } //10
		$a_01_1 = {25 73 25 73 5c 6b 65 79 34 2e 64 62 } //1 %s%s\key4.db
		$a_01_2 = {2f 75 70 2e 70 68 70 } //1 /up.php
		$a_01_3 = {5c 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 5c } //1 \Thunderbird\Profiles\
		$a_01_4 = {25 73 25 73 5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 %s%s\logins.json
		$a_01_5 = {2f 63 20 73 79 73 74 65 6d 69 6e 66 6f 20 3e } //1 /c systeminfo >
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}