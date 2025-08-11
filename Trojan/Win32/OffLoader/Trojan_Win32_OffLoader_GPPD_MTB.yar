
rule Trojan_Win32_OffLoader_GPPD_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {61 75 6e 74 62 65 72 72 79 2e 78 79 7a 2f 70 65 2f 73 74 61 72 74 2f 69 6e 64 65 78 2e 70 68 70 } //auntberry.xyz/pe/start/index.php  5
		$a_80_1 = {2f 56 45 52 59 53 49 4c 45 4e 54 } ///VERYSILENT  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}