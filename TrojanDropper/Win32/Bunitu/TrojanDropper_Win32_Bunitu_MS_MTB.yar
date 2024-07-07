
rule TrojanDropper_Win32_Bunitu_MS_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 11 89 15 90 01 04 8b 15 90 01 04 ff 35 90 01 04 8f 05 90 01 04 8b 3d 90 01 04 89 15 90 02 ac 33 3d 90 02 ac 8b cf 8b d1 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5f 5e 5d c3 90 00 } //1
		$a_00_1 = {69 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 5c 00 7b 00 } //1 interface\{
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}