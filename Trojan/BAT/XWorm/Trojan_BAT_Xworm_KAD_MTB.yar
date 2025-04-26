
rule Trojan_BAT_Xworm_KAD_MTB{
	meta:
		description = "Trojan:BAT/Xworm.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {6e 63 2e 62 6d 65 78 63 65 6c 6c 65 6e 74 66 6f 63 75 73 } //nc.bmexcellentfocus  2
		$a_80_1 = {53 65 63 75 72 69 74 79 48 65 61 6c 74 68 2e 62 69 6e } //SecurityHealth.bin  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}