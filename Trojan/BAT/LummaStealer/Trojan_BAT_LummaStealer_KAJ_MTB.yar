
rule Trojan_BAT_LummaStealer_KAJ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {51 50 62 77 57 4f 51 70 7a 54 55 } //QPbwWOQpzTU  1
		$a_80_1 = {64 4f 75 41 74 41 6e 5a 6f 4e } //dOuAtAnZoN  1
		$a_80_2 = {6d 65 49 78 57 61 71 49 58 75 4e 43 49 53 74 63 } //meIxWaqIXuNCIStc  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}