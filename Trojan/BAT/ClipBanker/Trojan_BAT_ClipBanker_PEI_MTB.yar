
rule Trojan_BAT_ClipBanker_PEI_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {01 23 00 56 00 71 00 51 00 40 00 40 00 4d 00 40 } //1 ⌁嘀焀儀䀀䀀䴀䀀
		$a_01_1 = {34 00 66 00 75 00 67 00 34 00 40 00 74 00 40 00 6e 00 4e 00 49 00 62 00 67 00 42 00 23 00 4d 00 30 00 68 00 56 00 47 00 68 00 70 00 63 00 79 00 42 00 77 00 63 00 6d 00 39 00 6e 00 63 00 6d 00 46 00 74 00 49 00 47 00 4e 00 68 00 62 00 6d 00 35 00 76 00 64 00 43 00 42 00 69 00 5a 00 53 00 42 00 79 00 64 00 57 00 34 00 67 00 61 00 57 00 34 00 67 00 } //1 4fug4@t@nNIbgB#M0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
		$a_01_2 = {63 00 33 00 59 00 23 00 56 00 6a 00 4e 00 23 00 59 00 78 00 4f 00 23 00 4d 00 30 00 5a 00 23 00 40 00 34 00 4f 00 53 00 4e 00 23 00 65 00 58 00 } //1 c3Y#VjN#YxO#M0Z#@4OSN#eX
		$a_01_3 = {6c 00 6f 00 69 00 6d 00 65 00 6e 00 73 00 61 00 74 00 75 00 72 00 6e 00 2e 00 65 00 78 00 65 00 } //1 loimensaturn.exe
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}