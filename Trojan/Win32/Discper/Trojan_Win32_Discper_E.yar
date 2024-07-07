
rule Trojan_Win32_Discper_E{
	meta:
		description = "Trojan:Win32/Discper.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 9d 8d 45 f0 50 3e ff 15 90 01 04 9c 58 05 90 01 04 2d 90 01 01 02 00 00 ff d0 c9 c3 00 90 00 } //1
		$a_03_1 = {57 68 d0 07 00 00 ff 15 90 01 04 68 90 01 04 33 f6 56 56 ff 15 90 01 04 ff 15 90 01 04 3d b7 00 00 00 75 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}