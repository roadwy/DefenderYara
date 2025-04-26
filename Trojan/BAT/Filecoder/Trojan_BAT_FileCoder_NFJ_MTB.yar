
rule Trojan_BAT_FileCoder_NFJ_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 3a 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? ?? ?? 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 73 ?? 00 00 0a 0a 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? ?? ?? 06 73 ?? 00 00 0a } //5
		$a_01_1 = {53 50 49 46 5f 53 57 45 44 57 49 4e 49 } //1 SPIF_SWEDWINI
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}