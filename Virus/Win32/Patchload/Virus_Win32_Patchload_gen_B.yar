
rule Virus_Win32_Patchload_gen_B{
	meta:
		description = "Virus:Win32/Patchload.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 72 65 73 73 68 63 41 64 64 68 74 50 72 6f 66 68 47 65 } //1 hresshcAddhtProfhGe
		$a_01_1 = {68 61 72 79 41 68 4c 69 62 72 68 4c 6f 61 64 } //1 haryAhLibrhLoad
		$a_01_2 = {66 6a 00 68 56 41 5f 58 } //1 橦栀䅖塟
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}