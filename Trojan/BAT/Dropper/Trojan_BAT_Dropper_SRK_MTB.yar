
rule Trojan_BAT_Dropper_SRK_MTB{
	meta:
		description = "Trojan:BAT/Dropper.SRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {14 0a 02 13 06 11 06 13 05 11 05 72 17 00 00 70 28 ?? ?? ?? 0a 2d 2c 11 05 72 4d 00 00 70 28 ?? ?? ?? 0a 2d 2d 11 05 72 9b 00 00 70 28 ?? ?? ?? 0a 2d 2e 11 05 72 b1 00 00 70 28 ?? ?? ?? 0a 2d 2f 2b 3e 72 11 01 00 70 0b 07 28 ?? ?? ?? 0a 0a 2b 2f 72 fe df 05 70 0c 08 28 ?? ?? ?? 0a 0a 2b 20 72 0b 1b 07 70 0d 09 28 ?? ?? ?? 0a 0a 2b 11 72 20 76 0d 70 13 04 11 04 28 ?? ?? ?? 0a 0a 2b 00 06 28 ?? ?? ?? 06 0a 06 28 ?? ?? ?? 0a 13 07 de 07 26 00 14 13 07 de 00 11 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}