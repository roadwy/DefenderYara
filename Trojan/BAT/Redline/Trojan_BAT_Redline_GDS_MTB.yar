
rule Trojan_BAT_Redline_GDS_MTB{
	meta:
		description = "Trojan:BAT/Redline.GDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0d 11 04 11 0d 17 59 99 02 7b 07 00 00 04 11 0d 99 06 5b 58 a1 00 11 0d 17 58 13 0d 11 0d 02 6f ?? ?? ?? 06 fe 04 13 0e 11 0e 2d d0 } //10
		$a_80_1 = {74 30 46 34 41 61 6e 54 6f 75 55 43 48 55 30 49 42 65 63 4e 71 } //t0F4AanTouUCHU0IBecNq  1
		$a_80_2 = {76 41 54 56 7a 64 43 64 64 6c 58 63 67 67 2f 78 6c 35 6e 72 6c 63 } //vATVzdCddlXcgg/xl5nrlc  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}