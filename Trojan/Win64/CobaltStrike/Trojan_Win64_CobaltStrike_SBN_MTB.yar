
rule Trojan_Win64_CobaltStrike_SBN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 0d 90 01 01 2c 07 88 44 0d 07 48 ff c1 48 83 f9 3c 72 90 00 } //1
		$a_03_1 = {0f b6 44 1d 90 01 01 8b 4d f7 32 c8 88 4c 1d fb 48 ff c3 48 83 fb 90 01 01 72 90 00 } //1
		$a_00_2 = {41 44 56 6f 62 66 75 73 63 61 74 6f 72 40 61 6e 64 72 69 76 65 74 } //1 ADVobfuscator@andrivet
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}