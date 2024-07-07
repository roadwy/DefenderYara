
rule Trojan_Win32_Dacic_HNA_MTB{
	meta:
		description = "Trojan:Win32/Dacic.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 68 6d 68 6d 64 73 2d 63 6b 6b } //1 vhmhmds-ckk
		$a_01_1 = {4b 6e 60 63 4b 68 61 71 60 71 78 40 } //1 Kn`cKhaq`qx@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}