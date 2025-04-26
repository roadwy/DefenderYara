
rule Trojan_BAT_Redline_GNT_MTB{
	meta:
		description = "Trojan:BAT/Redline.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 11 07 19 6f ?? ?? ?? 0a 11 08 11 09 6f ?? ?? ?? 0a 13 0a 11 05 11 04 11 07 1a 6f ?? ?? ?? 0a 11 08 11 09 6f ?? ?? ?? 0a 13 0b 11 0a 2c 07 11 0b 14 fe 01 2b 01 17 13 13 11 13 2c 05 dd ?? ?? ?? ?? 28 ?? ?? ?? 0a 11 0b 6f ?? ?? ?? 0a 17 8d ?? ?? ?? ?? 25 16 1f 24 9d 6f ?? ?? ?? 0a 13 0c 11 0c 2c 0a 11 0c 8e 69 1f 0d fe 04 2b 01 17 13 14 11 14 2c 05 } //10
		$a_01_1 = {48 79 64 65 72 61 62 61 64 2e 65 78 65 } //1 Hyderabad.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}