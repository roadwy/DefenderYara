
rule Trojan_BAT_Redline_GTV_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {13 0c 16 0c 08 12 0c 58 08 1f 3b 5e 1f 30 58 08 12 0c 58 46 61 52 08 17 58 0c 08 1f 11 37 e5 } //10
		$a_01_1 = {11 08 12 12 58 11 08 1f 3b 5e 1f 39 58 11 08 12 12 58 46 61 52 11 08 17 58 13 08 11 08 1f 0f } //10
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {50 72 6f 6a 65 63 74 33 35 2e 65 78 65 } //1 Project35.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}