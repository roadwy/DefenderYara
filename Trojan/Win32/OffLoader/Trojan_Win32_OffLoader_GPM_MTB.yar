
rule Trojan_Win32_OffLoader_GPM_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_80_0 = {76 61 73 65 6c 69 71 75 69 64 2e 78 79 7a 2f 70 65 2f 62 75 69 6c 64 2e 70 68 70 3f 70 65 3d } //vaseliquid.xyz/pe/build.php?pe=  5
		$a_80_1 = {73 69 73 74 65 72 6f 62 73 65 72 76 61 74 69 6f 6e 2e 69 63 75 2f 6d 6f 75 2e 70 68 70 3f 70 65 3d } //sisterobservation.icu/mou.php?pe=  5
		$a_80_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //Internet Explorer\Quick Launch  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*2) >=7
 
}