
rule Trojan_BAT_Lumma_RDB_MTB{
	meta:
		description = "Trojan:BAT/Lumma.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 61 6e 67 75 61 67 65 5f 73 75 70 70 6f 72 74 5f 61 6e 64 5f 6c 6f 63 61 6c 69 7a 61 74 69 6f 6e } //1 language_support_and_localization
		$a_01_1 = {7b 00 7d 00 64 00 7b 00 7d 00 6f 00 7b 00 7d 00 68 00 7b 00 7d 00 74 00 7b 00 7d 00 65 00 7b 00 7d 00 4d 00 7b 00 7d 00 74 00 7b 00 7d 00 65 00 7b 00 7d 00 47 00 7b 00 7d 00 } //1 {}d{}o{}h{}t{}e{}M{}t{}e{}G{}
		$a_01_2 = {3d 00 2f 00 2a 00 2d 00 54 00 3d 00 79 00 3d 00 70 00 3d 00 65 00 3d 00 } //1 =/*-T=y=p=e=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}