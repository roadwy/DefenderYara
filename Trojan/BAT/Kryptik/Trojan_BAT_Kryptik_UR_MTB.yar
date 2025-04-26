
rule Trojan_BAT_Kryptik_UR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 [0-04] 03 6f [0-09] 0c 06 08 6f [0-05] 06 18 6f [0-05] 06 6f [0-04] 02 16 02 8e 69 6f [0-04] 0d 09 13 04 2b 00 11 04 2a } //10
		$a_80_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //GetExportedTypes  2
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_3 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}