
rule Trojan_BAT_Racealer_MT_MTB{
	meta:
		description = "Trojan:BAT/Racealer.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2c 0b 06 6f [0-04] 28 [0-04] 2a 90 09 32 00 02 28 [0-04] 73 [0-04] 0a 28 [0-04] 14 fe [0-05] 73 [0-04] 6f [0-04] 06 6f [0-04] 7e [0-04] 28 } //1
		$a_81_1 = {5f 50 65 78 65 73 6f 47 6f } //1 _PexesoGo
		$a_81_2 = {5f 50 65 78 65 73 6f 57 61 69 74 } //1 _PexesoWait
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}