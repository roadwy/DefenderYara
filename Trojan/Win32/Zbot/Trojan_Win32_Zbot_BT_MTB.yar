
rule Trojan_Win32_Zbot_BT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 62 63 5a } //1 zkrvvcnmaebNbcZ
		$a_01_1 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 77 00 73 00 6e 00 70 00 6f 00 65 00 6d 00 5c 00 76 00 69 00 64 00 65 00 6f 00 2e 00 64 00 6c 00 6c 00 } //1 Application Data\wsnpoem\video.dll
		$a_01_2 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 58 4d 5a 5b 51 52 49 } //1 fk{vtelpp]hg[_\HXMZ[QRI
		$a_01_3 = {7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 5c 56 57 58 49 54 } //1 zkrvvcnmaebNUf\VWXIT
		$a_01_4 = {66 6b 7b 76 74 65 6c 70 70 5d 68 67 5b 5f 5c 48 61 51 54 50 51 47 4d 4a } //1 fk{vtelpp]hg[_\HaQTPQGMJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}