
rule Trojan_BAT_Jalapeno_BA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0d 08 09 16 09 8e 69 6f 7a 00 00 0a 26 07 09 6f 7b 00 00 0a 00 08 07 6f 7c 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}