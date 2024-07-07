
rule Trojan_Win32_Zenpack_MS_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {75 08 50 50 ff 90 02 05 e8 90 02 04 30 90 02 03 81 90 02 05 75 90 01 01 6a 00 90 02 0a ff 90 02 05 46 33 90 02 03 3b 90 02 03 90 18 81 90 00 } //1
		$a_02_1 = {75 08 50 50 ff 15 90 02 04 e8 90 02 04 30 90 02 03 81 ff 90 02 04 75 0f 6a 00 8d 90 02 03 50 6a 00 ff 15 90 02 04 46 33 90 02 03 3b 90 02 03 90 18 81 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}