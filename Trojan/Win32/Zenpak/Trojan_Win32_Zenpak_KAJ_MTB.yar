
rule Trojan_Win32_Zenpak_KAJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 65 77 77 64 65 6f 73 6a 65 68 74 46 73 65 63 6e 72 } //1 JewwdeosjehtFsecnr
		$a_01_1 = {6e 68 72 68 6c 39 37 2e 64 6c 6c } //1 nhrhl97.dll
		$a_01_2 = {48 4c 6f 61 64 4e 6f 6e 6c 6f 61 64 65 64 49 63 6f 6e 4f 76 65 72 6c 61 79 49 64 65 6e 74 69 66 69 65 72 73 } //1 HLoadNonloadedIconOverlayIdentifiers
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}