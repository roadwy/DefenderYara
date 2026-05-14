
rule Trojan_BAT_XWorm_GHT_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 02 28 ?? 00 00 0a 0b 1a 13 09 38 ?? fe ff ff 11 04 75 ?? 00 00 01 07 75 ?? 00 00 1b 16 07 75 ?? 00 00 1b 8e b7 6f ?? 01 00 0a 28 } //10
		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}