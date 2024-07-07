
rule Trojan_Win32_Nanocore_SD_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 02 90 34 e2 88 45 fb 90 90 ff 75 fc 8a 45 fb 90 59 88 01 } //1
		$a_01_1 = {8b c6 03 c3 90 c6 00 e4 90 90 90 90 90 43 81 fb 2f 5c c3 1c 75 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}