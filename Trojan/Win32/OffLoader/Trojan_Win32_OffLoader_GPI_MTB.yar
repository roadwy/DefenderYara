
rule Trojan_Win32_OffLoader_GPI_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {6e 69 67 68 74 61 75 74 68 6f 72 69 74 79 2e 78 79 7a 2f 72 6c 6f 2e 70 68 70 3f 64 } //nightauthority.xyz/rlo.php?d  5
		$a_80_1 = {6e 69 67 68 74 61 75 74 68 6f 72 69 74 79 2e 78 79 7a 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } //nightauthority.xyz/tracker/thank_you.php  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}