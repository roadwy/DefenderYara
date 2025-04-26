
rule Trojan_BAT_Redline_PAH_MTB{
	meta:
		description = "Trojan:BAT/Redline.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 08 04 08 1f 09 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 00 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07 31 dd } //10
		$a_01_1 = {4c 00 6a 00 72 00 6f 00 72 00 61 00 72 00 6a 00 64 00 72 00 } //1 Ljrorarjdr
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}