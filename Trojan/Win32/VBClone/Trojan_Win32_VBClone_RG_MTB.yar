
rule Trojan_Win32_VBClone_RG_MTB{
	meta:
		description = "Trojan:Win32/VBClone.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 61 00 61 00 61 00 61 00 00 00 00 00 40 00 1e 00 01 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4b 00 61 00 77 00 61 00 69 00 69 00 2d 00 55 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}