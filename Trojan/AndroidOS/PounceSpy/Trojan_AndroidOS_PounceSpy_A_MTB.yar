
rule Trojan_AndroidOS_PounceSpy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/PounceSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 42 75 66 66 65 72 54 6f 44 69 73 63 6f 72 64 41 6e 64 43 6c 65 61 72 } //1 sendBufferToDiscordAndClear
		$a_01_1 = {67 65 74 53 59 53 49 6e 66 6f } //1 getSYSInfo
		$a_01_2 = {69 73 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 45 6e 61 62 6c 65 64 46 6f 72 50 61 63 6b 61 67 65 } //1 isAccessibilityServiceEnabledForPackage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}