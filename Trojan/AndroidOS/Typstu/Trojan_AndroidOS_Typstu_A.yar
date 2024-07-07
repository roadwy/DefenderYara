
rule Trojan_AndroidOS_Typstu_A{
	meta:
		description = "Trojan:AndroidOS/Typstu.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 32 63 34 78 32 61 34 61 34 75 32 } //1 e2c4x2a4a4u2
		$a_01_1 = {63 6f 6d 2e 61 6e 64 2e 73 6e 64 2e 46 6c 61 73 68 6c 69 67 68 74 4c 45 44 53 65 72 76 69 63 65 } //1 com.and.snd.FlashlightLEDService
		$a_01_2 = {6d 74 2f 77 32 36 34 79 32 33 34 63 34 7a 32 79 32 } //1 mt/w264y234c4z2y2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}