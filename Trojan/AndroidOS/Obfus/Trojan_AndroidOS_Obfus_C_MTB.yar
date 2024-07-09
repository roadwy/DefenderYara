
rule Trojan_AndroidOS_Obfus_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Obfus.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 64 02 00 5c c7 ?? ?? 48 04 08 02 b0 41 d5 11 ff 00 70 40 ?? ?? 8c 12 ?? ?? ?? ?? ?? ?? ?? ?? 48 04 08 02 48 05 08 01 b0 54 d5 44 ff 00 5c c7 ?? ?? 1a 05 ?? ?? 48 05 0d 00 48 04 08 04 b7 54 8d 44 4f 04 03 00 1a 04 ?? ?? 5b c4 ?? ?? d8 00 00 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}