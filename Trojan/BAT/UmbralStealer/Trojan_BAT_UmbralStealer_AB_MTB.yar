
rule Trojan_BAT_UmbralStealer_AB_MTB{
	meta:
		description = "Trojan:BAT/UmbralStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 46 02 11 04 91 13 05 11 05 20 aa 00 00 00 61 d2 13 05 11 05 11 04 20 00 01 00 00 5d d2 59 d2 13 05 11 05 19 63 11 05 1b 62 60 d2 13 05 11 05 03 11 04 03 8e 69 5d 91 61 d2 13 05 09 11 04 11 05 9c 11 04 17 58 13 04 11 04 02 8e 69 32 b3 } //6
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_81_2 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 UnmapViewOfFile
		$a_81_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*6+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}