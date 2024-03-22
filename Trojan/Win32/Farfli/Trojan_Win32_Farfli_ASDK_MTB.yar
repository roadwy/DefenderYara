
rule Trojan_Win32_Farfli_ASDK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {32 d8 8a 0c b9 32 4d f0 02 cb 32 d1 8b 4d fc 28 16 0f b6 06 } //01 00 
		$a_01_1 = {6a 69 6e 6a 69 6e 2e 63 6f 6d } //01 00  jinjin.com
		$a_01_2 = {66 75 63 6b 79 6f 75 } //00 00  fuckyou
	condition:
		any of ($a_*)
 
}