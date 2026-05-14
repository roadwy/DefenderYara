
rule Trojan_BAT_ZhongStealer_A_AMTB{
	meta:
		description = "Trojan:BAT/ZhongStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 19 11 12 14 fe 03 33 0d 7e 07 00 00 04 1f 20 61 80 07 00 00 04 7e 07 00 00 04 20 f6 f1 f8 39 06 61 07 59 17 11 07 58 60 61 80 07 00 00 04 } //7
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*1) >=8
 
}