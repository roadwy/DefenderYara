
rule Trojan_BAT_Redline_GTN_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 03 08 17 58 03 8e 69 5d 91 59 ?? ?? ?? ?? ?? 58 17 58 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}