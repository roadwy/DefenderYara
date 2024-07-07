
rule Trojan_Win32_Fauppod_MR_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {52 54 43 59 56 55 59 42 2e 44 4c 4c } //1 RTCYVUYB.DLL
		$a_01_1 = {55 6a 6e 68 62 6a 49 67 76 62 68 } //1 UjnhbjIgvbh
		$a_01_2 = {41 63 74 66 76 79 67 52 63 79 } //1 ActfvygRcy
		$a_01_3 = {45 74 63 79 76 59 76 67 62 68 } //1 EtcyvYvgbh
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}