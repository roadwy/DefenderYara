
rule Trojan_AndroidOS_Hiddad_B{
	meta:
		description = "Trojan:AndroidOS/Hiddad.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 76 69 64 30 30 37 2f 76 69 64 65 6f 62 75 64 64 79 } //1 Lcom/vid007/videobuddy
		$a_01_1 = {6e 65 65 64 20 73 68 6f 77 20 72 65 77 61 72 64 20 61 64 } //1 need show reward ad
		$a_01_2 = {73 69 73 79 70 68 75 73 2f 6c 6f 63 6b 73 63 72 65 65 6e 73 } //1 sisyphus/lockscreens
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}