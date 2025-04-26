
rule Trojan_AndroidOS_Tetus_A{
	meta:
		description = "Trojan:AndroidOS/Tetus.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 74 79 70 65 3d 6d 61 72 6b 65 74 72 65 63 69 65 76 65 72 26 6c 6f 67 3d } //1 &type=marketreciever&log=
		$a_01_1 = {4d 61 72 6b 65 74 52 65 63 69 65 76 65 72 2e 6a 61 76 61 } //1 MarketReciever.java
		$a_01_2 = {74 65 74 75 6c 75 73 2e 63 6f 6d 2f 61 74 70 2d 61 6e 61 6c 79 74 69 63 73 2e 70 68 70 3f } //1 tetulus.com/atp-analytics.php?
		$a_01_3 = {26 74 79 70 65 3d 73 6d 73 72 65 63 69 65 76 65 72 26 6c 6f 67 3d } //1 &type=smsreciever&log=
		$a_01_4 = {2f 5f 5f 75 74 6d 2e 67 69 66 } //1 /__utm.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}