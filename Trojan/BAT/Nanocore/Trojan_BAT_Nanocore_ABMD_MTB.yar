
rule Trojan_BAT_Nanocore_ABMD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 08 5d 91 28 ?? ?? ?? 0a 59 06 58 06 5d d2 0d 2b 00 09 2a } //5
		$a_01_1 = {6b 00 62 00 57 00 61 00 72 00 2e 00 4c 00 65 00 67 00 6f 00 } //1 kbWar.Lego
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}