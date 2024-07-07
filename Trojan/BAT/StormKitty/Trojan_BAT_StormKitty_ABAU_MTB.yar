
rule Trojan_BAT_StormKitty_ABAU_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.ABAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 16 1f 1a 6f 90 01 03 0a 0b 07 1f 41 58 28 90 01 03 0a 0d 08 12 03 28 90 01 03 0a 28 90 01 03 0a 0c 00 11 04 17 58 13 04 11 04 02 fe 04 13 05 11 05 2d cb 90 00 } //1
		$a_01_1 = {47 65 74 41 6e 74 69 76 69 72 75 73 } //1 GetAntivirus
		$a_01_2 = {57 69 6e 64 6f 77 73 43 61 72 65 2e 59 61 6e 42 6f 74 6e 65 74 48 65 6c 70 65 72 2e 55 74 69 6c 69 74 79 } //1 WindowsCare.YanBotnetHelper.Utility
		$a_01_3 = {24 36 63 63 36 39 65 39 33 2d 31 61 37 30 2d 34 38 65 39 2d 38 64 62 38 2d 39 63 64 64 63 64 63 66 30 32 33 38 } //1 $6cc69e93-1a70-48e9-8db8-9cddcdcf0238
		$a_01_4 = {59 00 61 00 6e 00 20 00 42 00 6f 00 74 00 6e 00 65 00 74 00 20 00 44 00 65 00 6d 00 6f 00 20 00 31 00 20 00 7c 00 7c 00 20 00 59 00 61 00 6e 00 20 00 54 00 65 00 63 00 68 00 } //1 Yan Botnet Demo 1 || Yan Tech
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}