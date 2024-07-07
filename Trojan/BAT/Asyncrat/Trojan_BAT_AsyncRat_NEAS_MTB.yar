
rule Trojan_BAT_AsyncRat_NEAS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 80 0a 00 00 04 28 90 01 01 00 00 0a 80 07 00 00 04 28 0d 00 00 06 7e 09 00 00 04 6f 90 01 01 00 00 0a 7e 08 00 00 04 6f 90 01 01 00 00 0a 0a 7e 08 00 00 04 6f 90 01 01 00 00 0a 06 2a 90 00 } //10
		$a_01_1 = {25 00 42 00 41 00 54 00 43 00 48 00 4e 00 41 00 4d 00 45 00 25 00 } //2 %BATCHNAME%
		$a_01_2 = {42 2e 74 65 78 74 } //2 B.text
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}