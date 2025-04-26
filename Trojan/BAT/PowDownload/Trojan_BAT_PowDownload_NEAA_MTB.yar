
rule Trojan_BAT_PowDownload_NEAA_MTB{
	meta:
		description = "Trojan:BAT/PowDownload.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 03 00 fe 0c 04 00 93 fe 0e 05 00 fe 0c 00 00 fe 0c 05 00 fe 09 02 00 59 d1 6f 0c 00 00 0a 26 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04 00 fe 0c 03 00 8e 69 32 c5 } //10
		$a_01_1 = {4c 49 4c 55 5a 49 56 45 52 54 2e 65 78 65 } //5 LILUZIVERT.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}