
rule Trojan_Win32_Farfli_ASDK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 d8 8a 0c b9 32 4d f0 02 cb 32 d1 8b 4d fc 28 16 0f b6 06 } //3
		$a_01_1 = {6a 69 6e 6a 69 6e 2e 63 6f 6d } //1 jinjin.com
		$a_01_2 = {66 75 63 6b 79 6f 75 } //1 fuckyou
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}