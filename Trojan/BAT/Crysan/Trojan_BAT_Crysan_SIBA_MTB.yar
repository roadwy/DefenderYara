
rule Trojan_BAT_Crysan_SIBA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {9d 1d 8d 27 ?? ?? ?? fe 0e ?? ?? [0-50] fe 0c 90 1b 01 1c 1f 6d 9d [0-60] fe 0c 90 1b 01 1b 1f 61 9d [0-60] fe 0c 90 1b 01 1a 1f 72 9d [0-60] fe 0c 90 1b 01 19 1f 67 9d [0-60] fe 0c 90 1b 01 18 1f 6f 9d [0-60] fe 0c 90 1b 01 17 1f 72 9d [0-60] fe 0c 90 1b 01 16 1f 50 9d } //1
		$a_03_1 = {9d 1a 8d 27 ?? ?? ?? fe 0e ?? ?? [0-50] fe 0c 90 1b 01 19 1f 65 9d [0-50] fe 0c 90 1b 01 18 1f 6d 9d [0-50] fe 0c 90 1b 01 17 1f 61 9d [0-50] fe 0c 90 1b 01 16 1f 4e 9d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}