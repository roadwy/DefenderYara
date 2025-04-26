
rule Trojan_Win32_DCRat_SOL_MTB{
	meta:
		description = "Trojan:Win32/DCRat.SOL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 11 09 00 00 83 c4 04 eb 02 33 c0 57 ff 75 f8 89 45 fc 50 89 7e 10 89 5e 14 e8 6a 16 00 00 8b 5d fc 83 c4 0c 8b 45 f4 c6 04 1f 00 83 f8 10 72 29 8d 48 01 8b 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}