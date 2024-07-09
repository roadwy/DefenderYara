
rule Trojan_BAT_Remcos_GAN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 33 2b 34 72 ?? ?? ?? 70 2b 34 2b 39 2b 3e 2b 3f 2b 40 6f ?? ?? ?? 0a 06 18 6f ?? ?? ?? 0a 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}