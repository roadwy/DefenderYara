
rule Trojan_Win32_FlyStudio_AFS_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.AFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 d8 1b c0 8b 7f 08 25 00 00 00 08 50 6a 01 ff 75 14 ff 75 10 ff 75 1c ff 75 0c 57 ff 15 18 59 60 00 } //1
		$a_01_1 = {8b 46 34 83 c4 0c 89 46 38 8d 45 fc 50 8b 45 08 2b fb 03 c3 57 50 ff 76 14 ff 15 20 59 60 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}