
rule Trojan_Win32_Offloader_KAS_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 62 69 74 65 64 75 63 6b 73 2e 73 62 73 2f 62 65 61 2e 70 68 70 } ///biteducks.sbs/bea.php  10
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}