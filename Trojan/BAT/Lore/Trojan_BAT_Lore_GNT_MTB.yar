
rule Trojan_BAT_Lore_GNT_MTB{
	meta:
		description = "Trojan:BAT/Lore.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c 38 52 00 00 00 20 0e } //10
		$a_80_1 = {45 6d 69 6e 65 6d 2e 64 6c 6c } //Eminem.dll  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}