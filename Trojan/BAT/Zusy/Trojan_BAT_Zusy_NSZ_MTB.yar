
rule Trojan_BAT_Zusy_NSZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 07 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 06 20 ?? ?? ?? 00 0d 12 03 6f ?? ?? ?? 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 73 ?? ?? ?? 06 0a 16 28 ?? ?? ?? 06 39 ?? ?? ?? 00 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {64 6f 6f 72 69 6e 62 6f 6f 6b 5f 38 34 37 32 31 34 } //1 doorinbook_847214
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}