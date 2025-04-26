
rule Trojan_Win32_OffLoader_SAA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 66 72 6f 6e 74 74 68 72 6f 61 74 2e 78 79 7a 2f 6a 65 74 6f 2e 70 68 70 } ////frontthroat.xyz/jeto.php  2
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_2 = {2f 77 65 61 6b 73 65 63 75 72 69 74 79 } ///weaksecurity  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}