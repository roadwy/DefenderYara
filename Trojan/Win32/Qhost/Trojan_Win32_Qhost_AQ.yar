
rule Trojan_Win32_Qhost_AQ{
	meta:
		description = "Trojan:Win32/Qhost.AQ,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 0f 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 2f 67 6f 2e 70 68 70 3f 67 63 6f 64 65 3d 25 73 } //0a 00  http://%s/go.php?gcode=%s
		$a_01_1 = {61 63 74 2e 61 75 74 6f 2d 63 6f 64 65 63 2e 63 6f 6d } //01 00  act.auto-codec.com
		$a_01_2 = {73 68 6f 70 72 69 6e 6e 61 69 2e 63 6f 6d } //01 00  shoprinnai.com
		$a_01_3 = {6b 74 63 61 73 68 6d 61 6c 6c 2e 63 6f 6d } //01 00  ktcashmall.com
		$a_01_4 = {65 6d 61 72 74 2e 63 6f 2e 6b 72 } //01 00  emart.co.kr
		$a_01_5 = {68 6f 77 6d 61 69 6c 2e 6e 65 74 } //01 00  howmail.net
		$a_01_6 = {62 61 69 64 75 2e 63 6f 6d } //01 00  baidu.com
		$a_01_7 = {78 70 6f 72 6e 6f 73 69 74 65 2e 63 6f 6d } //01 00  xpornosite.com
		$a_01_8 = {78 78 78 70 61 72 61 73 69 74 65 2e 63 6f 6d } //01 00  xxxparasite.com
		$a_01_9 = {73 65 78 79 74 6f 75 72 2e 6e 65 74 } //01 00  sexytour.net
		$a_01_10 = {73 65 78 79 34 75 2e 63 6f 2e 6b 72 } //01 00  sexy4u.co.kr
		$a_01_11 = {70 6f 72 6e 6f 74 6f 77 6e 2e 6e 65 74 } //01 00  pornotown.net
		$a_01_12 = {68 75 73 6c 65 72 2e 63 6f 2e 6b 72 } //01 00  husler.co.kr
		$a_01_13 = {6e 61 76 65 72 2e 63 6f 6d } //01 00  naver.com
		$a_01_14 = {79 61 68 6f 6f 2e 63 6f 6d } //00 00  yahoo.com
	condition:
		any of ($a_*)
 
}