
rule Trojan_Win32_TrickBot_DSR_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 2c a1 90 01 04 33 c5 89 45 fc 33 c0 0f b6 88 90 01 04 81 f9 ff 00 00 00 0f 87 90 01 04 ff 24 8d 90 00 } //1
		$a_02_1 = {3d 05 2e 00 00 0f 83 90 01 04 c6 80 90 01 04 00 e9 90 01 04 c6 80 90 01 04 01 e9 90 01 04 c6 80 90 01 04 02 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}