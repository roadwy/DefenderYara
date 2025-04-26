
rule Ransom_Win32_Genasom_Z{
	meta:
		description = "Ransom:Win32/Genasom.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 6a 1a 53 ff 15 ?? ?? ?? ?? 85 c0 7c 7e 68 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 68 53 6a 02 6a 02 53 53 6a 02 } //1
		$a_01_1 = {49 45 44 61 74 61 46 65 65 64 65 72 2e 64 6c 6c 00 } //1
		$a_00_2 = {6d 00 65 00 64 00 69 00 61 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 2e 00 78 00 73 00 6c 00 } //1 mediamodule.xsl
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}