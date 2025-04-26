
rule Trojan_BAT_Psdownload_PGP_MTB{
	meta:
		description = "Trojan:BAT/Psdownload.PGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {72 65 66 73 2f 68 65 61 64 73 2f 6d 61 69 6e 2f 4d 61 73 6f 6e 52 6f 6f 74 6b 69 74 2e 65 78 65 } //refs/heads/main/MasonRootkit.exe  1
		$a_80_1 = {44 69 73 61 62 6c 65 2d 57 69 6e 64 6f 77 73 2d 44 65 66 65 6e 64 65 72 2f 6d 61 69 6e 2f 73 6f 75 72 63 65 2e 62 61 74 } //Disable-Windows-Defender/main/source.bat  4
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*4) >=5
 
}