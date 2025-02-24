
rule Trojan_BAT_Remcos_BA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 91 03 08 03 6f 05 00 00 0a 5d 6f 06 00 00 0a 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}