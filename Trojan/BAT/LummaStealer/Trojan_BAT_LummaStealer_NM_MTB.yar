
rule Trojan_BAT_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 7e 00 00 01 13 14 11 09 28 ?? 07 00 0a 16 11 14 16 1a 28 ?? 07 00 0a 11 0a 28 ?? 07 00 0a 16 11 14 } //3
		$a_01_1 = {46 65 72 6e 61 6e 64 6f 4b 61 70 5f 64 69 67 69 74 61 6c 45 55 } //1 FernandoKap_digitalEU
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_LummaStealer_NM_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0b 00 00 06 73 ?? 00 00 06 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? 00 00 06 15 7e ?? 00 00 04 16 8f ?? 00 00 01 7e ?? 00 00 04 8e 69 1f 40 12 00 28 0a 00 00 06 } //3
		$a_03_1 = {26 16 0b 20 88 01 00 00 0c 16 16 7e ?? 00 00 04 08 8f ?? 00 00 01 7e ?? 00 00 04 16 12 01 28 08 00 00 06 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_BAT_LummaStealer_NM_MTB_3{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 69 6f 6c 65 74 52 69 63 68 50 6c 61 79 65 72 33 36 34 44 61 76 69 64 2e 5a 4f 44 76 6c } //2 VioletRichPlayer364David.ZODvl
		$a_01_1 = {74 65 61 63 68 20 77 65 20 73 6f 6c 75 74 69 6f 6e 20 6d 6f 64 75 6c 65 20 69 20 63 6f 6e 6e 65 63 74 20 73 68 65 20 69 20 73 65 72 76 69 63 65 20 73 68 65 } //2 teach we solution module i connect she i service she
		$a_01_2 = {73 79 73 74 65 6d 20 72 6f 75 67 68 20 63 6f 6e 6e 65 63 74 20 65 78 70 6c 6f 72 65 20 70 72 6f 6a 65 63 74 } //2 system rough connect explore project
		$a_01_3 = {24 62 32 61 37 31 34 32 63 2d 62 35 61 34 2d 34 31 36 62 2d 39 30 62 64 2d 63 66 33 36 33 32 36 39 34 62 65 38 } //1 $b2a7142c-b5a4-416b-90bd-cf3632694be8
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}