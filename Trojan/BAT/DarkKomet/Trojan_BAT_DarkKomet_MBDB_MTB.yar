
rule Trojan_BAT_DarkKomet_MBDB_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.MBDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 03 50 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 73 0c 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 02 50 16 02 50 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //10
		$a_01_1 = {57 69 6e 33 32 48 65 6c 70 65 72 } //1 Win32Helper
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}