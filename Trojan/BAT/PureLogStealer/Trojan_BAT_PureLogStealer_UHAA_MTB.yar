
rule Trojan_BAT_PureLogStealer_UHAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.UHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 03 95 11 06 11 04 95 58 d2 13 0f 38 } //2
		$a_01_1 = {11 0e 11 10 61 13 13 38 } //2 ฑထ፡㠓
		$a_01_2 = {38 00 30 00 48 00 44 00 46 00 38 00 38 00 4b 00 34 00 45 00 44 00 30 00 55 00 35 00 35 00 50 00 48 00 48 00 47 00 38 00 4e 00 34 00 } //1 80HDF88K4ED0U55PHHG8N4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}