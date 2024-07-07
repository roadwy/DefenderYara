
rule Trojan_Win64_IcedId_PAG_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 61 62 } //1 scab
		$a_01_1 = {51 74 35 4d 75 6c 74 69 6d 65 64 69 61 2e 70 64 62 } //1 Qt5Multimedia.pdb
		$a_01_2 = {6e 67 40 40 51 45 48 41 41 3f 41 56 31 40 58 5a } //1 ng@@QEHAA?AV1@XZ
		$a_01_3 = {71 77 72 69 74 61 62 6c 65 43 68 61 6e 67 65 64 40 51 4d 65 74 61 44 61 74 61 57 72 69 74 65 72 43 6f 6e 74 72 6f 6c 40 40 51 45 41 41 58 5f 4e 40 5a } //1 qwritableChanged@QMetaDataWriterControl@@QEAAX_N@Z
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}