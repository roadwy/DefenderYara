
rule Backdoor_BAT_Coroxy_NA_MTB{
	meta:
		description = "Backdoor:BAT/Coroxy.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 7c 6a 00 00 28 ?? ?? 00 06 2b 3c 28 ?? ?? 00 0a 08 6f ?? ?? 00 0a 2b 24 07 8e 69 8d ?? ?? 00 01 13 04 16 13 05 2b 23 11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 2b 03 0d 2b d9 11 05 17 58 13 05 2b 03 0c 2b c1 11 05 07 8e 69 32 02 2b 05 } //5
		$a_01_1 = {45 67 6b 77 6c 6e 69 77 78 72 } //1 Egkwlniwxr
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}