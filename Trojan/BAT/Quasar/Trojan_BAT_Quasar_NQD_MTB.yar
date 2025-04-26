
rule Trojan_BAT_Quasar_NQD_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 95 58 20 01 60 9f de 61 9e 11 0b 20 ?? ?? ?? 60 5a 20 ?? ?? ?? af 61 38 ?? ?? ?? ff 08 08 5a 20 ?? ?? ?? 14 6a 5e 0c 20 a7 91 bd 2d } //5
		$a_01_1 = {6a 00 75 00 73 00 63 00 68 00 65 00 64 00 } //1 jusched
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}