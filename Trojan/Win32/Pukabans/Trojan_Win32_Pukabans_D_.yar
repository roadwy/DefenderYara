
rule Trojan_Win32_Pukabans_D_{
	meta:
		description = "Trojan:Win32/Pukabans.D!!Pukabans.D!dha,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 ff 00 04 00 00 75 ?? 33 db 53 53 53 68 ?? ?? ?? ?? 53 53 [0-01] e8 [0-10] 81 ff 63 04 00 00 75 } //10
		$a_01_1 = {81 ff 64 04 00 00 75 } //10
		$a_01_2 = {81 ff 05 04 00 00 75 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}