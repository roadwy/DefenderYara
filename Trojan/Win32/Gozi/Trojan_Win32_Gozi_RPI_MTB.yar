
rule Trojan_Win32_Gozi_RPI_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d c8 8a 34 1e 32 34 0f 8b 4d d8 88 34 19 8b 4d b8 8b 75 f0 39 f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}