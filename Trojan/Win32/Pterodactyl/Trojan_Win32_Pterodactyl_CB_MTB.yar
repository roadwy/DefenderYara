
rule Trojan_Win32_Pterodactyl_CB_MTB{
	meta:
		description = "Trojan:Win32/Pterodactyl.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 6f 6f 2e 64 6c 6c } //1 rootoo.dll
		$a_01_1 = {53 63 74 76 79 67 46 63 67 68 } //1 SctvygFcgh
		$a_01_2 = {52 66 76 62 68 53 66 63 76 62 68 } //1 RfvbhSfcvbh
		$a_01_3 = {53 66 76 67 4a 75 69 6d } //1 SfvgJuim
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}