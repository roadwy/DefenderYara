
rule Trojan_BAT_FileCoder_NF_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 17 28 ?? 00 00 06 02 02 04 28 ?? 00 00 06 16 28 ?? 00 00 06 28 ?? 00 00 06 16 28 ?? 00 00 06 0b } //5
		$a_01_1 = {4f 6e 79 78 4c 6f 63 6b 65 72 } //1 OnyxLocker
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}