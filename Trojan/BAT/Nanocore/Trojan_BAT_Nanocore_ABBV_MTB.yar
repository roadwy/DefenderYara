
rule Trojan_BAT_Nanocore_ABBV_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_1 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {24 38 62 64 39 35 63 36 63 2d 66 33 32 34 2d 34 33 30 35 2d 39 30 65 31 2d 61 37 66 63 62 64 32 36 32 64 66 33 } //1 $8bd95c6c-f324-4305-90e1-a7fcbd262df3
		$a_01_4 = {43 00 61 00 6e 00 76 00 61 00 73 00 2e 00 49 00 6d 00 61 00 67 00 65 00 } //1 Canvas.Image
		$a_01_5 = {54 00 75 00 6d 00 61 00 73 00 } //1 Tumas
		$a_01_6 = {54 00 75 00 6d 00 61 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Tuma.Properties.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}