
rule Trojan_Win32_Emotet_RPI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {9c 3f 61 f0 27 96 82 6b 5d 26 33 21 b8 5b ce 4e 9c 5e 38 72 42 } //00 00 
	condition:
		any of ($a_*)
 
}