
rule Trojan_Win32_Zusy_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 00 80 72 02 00 80 3a 9b 00 00 94 02 00 80 48 9b 00 00 5e 9b 00 00 } //10
		$a_80_1 = {62 62 67 67 74 74 68 2e 65 78 65 } //bbggtth.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}