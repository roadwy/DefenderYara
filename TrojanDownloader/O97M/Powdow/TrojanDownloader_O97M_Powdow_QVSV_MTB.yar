
rule TrojanDownloader_O97M_Powdow_QVSV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.QVSV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 51 6d 76 76 20 3d 20 45 6e 76 69 72 6f 6e 24 28 43 65 6c 6c 73 28 32 2c 20 31 29 29 } //1 LQmvv = Environ$(Cells(2, 1))
		$a_01_1 = {57 56 52 63 46 44 2e 4e 61 6d 65 73 70 61 63 65 28 4c 51 6d 76 76 29 2e 53 65 6c 66 2e 49 6e 76 6f 6b 65 56 65 72 62 20 22 50 61 73 74 65 } //1 WVRcFD.Namespace(LQmvv).Self.InvokeVerb "Paste
		$a_01_2 = {4e 61 6d 65 20 4c 51 6d 76 76 20 2b 20 22 5c 7a 6c 56 72 69 2e 74 78 74 22 20 41 73 20 4c 51 6d 76 76 20 2b 20 22 5c 7a 6c 56 72 69 2e 6a 73 } //1 Name LQmvv + "\zlVri.txt" As LQmvv + "\zlVri.js
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}