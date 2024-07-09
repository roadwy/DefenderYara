
rule Trojan_BAT_ClipBanker_AC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 1f 23 28 ?? ?? ?? 0a 72 35 00 00 70 28 ?? ?? ?? 0a 13 05 11 05 18 18 73 08 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_ClipBanker_AC_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 27 06 02 07 6f ?? ?? ?? 0a 7e 3a 00 00 04 07 7e 3a 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 } //2
		$a_01_1 = {54 72 61 66 66 69 63 50 72 6f 67 72 61 6d 6d 65 72 76 32 2e 65 78 65 } //1 TrafficProgrammerv2.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}