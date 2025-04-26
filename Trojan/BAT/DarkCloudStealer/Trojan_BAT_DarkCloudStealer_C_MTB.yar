
rule Trojan_BAT_DarkCloudStealer_C_MTB{
	meta:
		description = "Trojan:BAT/DarkCloudStealer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 8e 69 5d 02 06 09 28 } //2
		$a_01_1 = {09 15 58 0d } //2 ᔉ൘
		$a_03_2 = {03 04 03 8e 69 5d 91 06 04 1f ?? 5d 91 61 28 ?? 00 00 0a 03 04 17 58 03 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}