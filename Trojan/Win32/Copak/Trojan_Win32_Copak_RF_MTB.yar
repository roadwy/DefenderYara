
rule Trojan_Win32_Copak_RF_MTB{
	meta:
		description = "Trojan:Win32/Copak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 a0 36 4b 00 c3 90 02 09 52 ca 4e 00 90 02 30 31 90 00 } //01 00 
		$a_01_1 = {09 f6 c3 09 db 21 f3 81 eb f2 ce 6b ed } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {96 87 a7 00 90 02 15 8a 89 a7 00 90 02 40 31 90 02 35 ac 89 a7 00 0f 8c 90 01 01 ff ff ff 90 00 } //01 00 
		$a_01_1 = {68 74 6f 4d 76 4c 41 61 } //01 00  htoMvLAa
		$a_01_2 = {5a 7a 4b 48 49 45 6f 4d 67 } //00 00  ZzKHIEoMg
	condition:
		any of ($a_*)
 
}