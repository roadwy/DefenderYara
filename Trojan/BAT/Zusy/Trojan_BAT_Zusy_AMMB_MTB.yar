
rule Trojan_BAT_Zusy_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a fe 09 00 00 7b ?? 00 00 04 fe 09 00 00 7b ?? 00 00 04 6f ?? 00 00 0a fe 09 01 00 20 ?? ?? ?? ?? fe 09 01 00 8e 69 6f ?? 00 00 0a 2a } //2
		$a_80_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 61 63 68 65 4d 65 6d 6f 72 79 } //Select * from Win32_CacheMemory  1
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*1) >=3
 
}