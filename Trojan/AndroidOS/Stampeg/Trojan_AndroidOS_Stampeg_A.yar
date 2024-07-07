
rule Trojan_AndroidOS_Stampeg_A{
	meta:
		description = "Trojan:AndroidOS/Stampeg.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 67 68 61 76 61 2f 6b 69 63 6b 65 72 } //1 Moghava/kicker
		$a_01_1 = {73 64 63 61 72 64 2f 44 43 49 4d 2f 43 61 6d 65 72 61 2f } //1 sdcard/DCIM/Camera/
		$a_01_2 = {73 74 61 6d 70 65 72 2e 6a 61 76 61 } //1 stamper.java
		$a_01_3 = {6b 69 63 6b 65 72 2e 6a 61 76 61 } //1 kicker.java
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}