
rule Trojan_BAT_Amadey_AA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 17 59 8d ?? ?? ?? 01 0c 07 07 8e 69 17 59 91 0d 16 13 05 2b 20 08 11 05 07 11 05 91 06 11 05 06 8e 69 5d 91 09 58 20 ?? ?? ?? 00 5f 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 17 59 fe 02 16 fe 01 13 06 11 06 2d ce } //1
		$a_01_1 = {6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 41 00 64 00 64 00 2d 00 } //1 ll.exe  -Command Add-
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}