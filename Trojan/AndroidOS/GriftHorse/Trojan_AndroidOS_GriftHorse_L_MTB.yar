
rule Trojan_AndroidOS_GriftHorse_L_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 00 14 04 ?? ?? 0b 7f 6e 20 ?? ?? 43 00 14 04 ?? ?? 08 7f 6e 20 ?? ?? 43 00 0c 04 1f 04 ?? ?? 5b 34 ?? ?? 6e 10 ?? ?? 04 00 0c 04 12 10 6e 20 ?? ?? 04 00 54 34 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 04 00 54 34 ?? ?? 22 00 ?? ?? 70 20 ?? ?? 30 00 6e 20 ?? ?? 04 00 6e 10 ?? ?? 03 00 0c 04 54 30 ?? ?? 71 20 ?? ?? 04 00 6e 10 ?? ?? 03 00 0c 04 1a 00 ?? ?? 71 20 ?? ?? 04 00 0c 04 54 30 [0-28] 54 32 ?? ?? 6e 20 ?? ?? 21 00 6e 20 ?? ?? 41 00 6e 10 ?? ?? 01 00 0c 04 6e 20 ?? ?? 40 00 } //10
		$a_03_1 = {32 00 14 03 ?? ?? 0a 7f 6e 20 ?? ?? 32 00 14 03 ?? ?? 07 7f 6e 20 ?? ?? 32 00 0c 03 1f 03 ?? ?? 6e 10 ?? ?? 03 00 0c 00 12 11 6e 20 ?? ?? 10 00 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 22 00 ?? ?? 70 20 ?? ?? 20 00 6e 20 ?? ?? 03 00 6e 10 ?? ?? 02 00 0c 00 71 20 ?? ?? 30 00 [0-05] 6e 20 ?? ?? 03 00 } //10
		$a_03_2 = {0c 00 60 01 ?? ?? 6e 20 ?? ?? 13 00 0c 01 1f 01 ?? ?? 71 20 ?? ?? 10 00 60 00 ?? ?? 6e 20 ?? ?? 03 00 0c 00 1f 00 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 6e 20 ?? ?? 41 00 6e 10 ?? ?? 01 00 0c 04 6e 20 ?? ?? 40 00 } //10
		$a_03_3 = {70 73 3a 2f 2f 64 [0-17] 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e [0-35] 2e 68 74 6d 6c } //5
		$a_00_4 = {6c 69 74 65 6f 66 66 65 72 73 61 70 70 73 2d 65 75 2e 73 33 2e 65 75 2d 63 65 6e 74 72 61 6c 2d 31 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 63 6f 6d 2e 74 75 72 62 6f 2e 66 75 6e 67 61 6d 65 73 2e 68 74 6d 6c } //5 liteoffersapps-eu.s3.eu-central-1.amazonaws.com/com.turbo.fungames.html
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*5+(#a_00_4  & 1)*5) >=15
 
}