
rule Trojan_BAT_Filecoder_MBZ_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 02 06 07 28 ?? 00 00 06 0c 03 08 28 ?? 00 00 0a 00 03 03 72 ff 00 00 70 } //2
		$a_01_1 = {36 34 62 35 34 66 34 61 63 62 38 64 } //1 64b54f4acb8d
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}