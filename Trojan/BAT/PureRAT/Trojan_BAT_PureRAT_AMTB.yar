
rule Trojan_BAT_PureRAT_AMTB{
	meta:
		description = "Trojan:BAT/PureRAT!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {45 6e 75 6d 50 75 72 65 43 72 79 70 74 65 72 49 6e 6a 65 63 74 69 6f 6e } //EnumPureCrypterInjection  1
		$a_80_1 = {45 6e 75 6d 50 75 72 65 43 72 79 70 74 65 72 46 61 6b 65 41 70 70 } //EnumPureCrypterFakeApp  1
		$a_80_2 = {45 6e 75 6d 50 75 72 65 43 72 79 70 74 65 72 53 74 61 72 74 75 70 } //EnumPureCrypterStartup  1
		$a_80_3 = {45 6e 75 6d 50 75 72 65 43 72 79 70 74 65 72 46 61 6b 65 4d 65 73 73 61 67 65 54 79 70 65 } //EnumPureCrypterFakeMessageType  1
		$a_80_4 = {50 75 72 65 52 41 54 2e 65 78 65 } //PureRAT.exe  1
		$a_80_5 = {50 75 72 65 48 56 4e 43 5f 4c 69 62 2e 45 6e 75 6d 73 } //PureHVNC_Lib.Enums  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}