
rule Trojan_BAT_Xmrig_RDA_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {34 63 37 61 64 30 32 37 2d 32 31 64 66 2d 34 66 32 61 2d 39 36 35 33 2d 62 30 66 63 36 33 63 37 64 62 61 65 } //1 4c7ad027-21df-4f2a-9653-b0fc63c7dbae
		$a_01_1 = {48 61 73 68 56 61 75 6c 74 58 4d 52 69 67 4d 69 6e 65 72 } //1 HashVaultXMRigMiner
		$a_01_2 = {2f 00 2f 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 2e 00 70 00 68 00 2f 00 76 00 61 00 75 00 6c 00 74 00 2d 00 77 00 6f 00 72 00 6b 00 65 00 72 00 73 00 2d 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 2d 00 33 00 2d 00 31 00 31 00 2d 00 31 00 31 00 } //1 //telegra.ph/vault-workers-controller-3-11-11
		$a_01_3 = {68 00 6e 00 63 00 78 00 6d 00 2e 00 65 00 78 00 65 00 } //1 hncxm.exe
		$a_01_4 = {47 00 4f 00 4d 00 58 00 72 00 69 00 67 00 } //1 GOMXrig
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}