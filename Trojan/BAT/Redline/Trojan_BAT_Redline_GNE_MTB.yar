
rule Trojan_BAT_Redline_GNE_MTB{
	meta:
		description = "Trojan:BAT/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 07 09 11 08 11 05 11 06 6f ?? ?? ?? 0a 13 08 28 ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a 17 8d ?? ?? ?? ?? 25 16 1f 24 9d 6f ?? ?? ?? 0a 13 09 08 11 04 1b 6f ?? ?? ?? 0a 13 0a 08 11 04 1c 6f ?? ?? ?? 0a 13 0b 09 11 0a 11 05 11 06 6f ?? ?? ?? 0a 13 0a 09 11 0b 11 05 11 06 6f ?? ?? ?? 0a 13 0b 07 28 ?? ?? ?? 0a 8c ?? ?? ?? ?? 11 09 1a 9a 14 11 09 } //10
		$a_80_1 = {79 5a 43 79 51 52 4a 4c 4c 74 65 57 74 48 63 78 74 6a 47 50 67 4c 36 4e 63 64 } //yZCyQRJLLteWtHcxtjGPgL6Ncd  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}