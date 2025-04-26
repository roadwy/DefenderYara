
rule Trojan_BAT_SpyNoon_AR_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 5d 08 58 13 10 11 10 08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13 11 13 20 00 04 00 00 58 } //4
		$a_01_1 = {48 00 46 00 34 00 34 00 50 00 37 00 38 00 52 00 5a 00 34 00 38 00 4a 00 55 00 59 00 49 00 42 00 47 00 47 00 35 00 34 00 50 00 34 00 } //1 HF44P78RZ48JUYIBGG54P4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}