
rule Ransom_Win64_Hazcod_AA_MTB{
	meta:
		description = "Ransom:Win64/Hazcod.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 77 73 61 69 6f 63 74 6c 20 28 66 6f 72 63 65 64 29 20 2d 3e 20 6e 6f 64 65 3d 20 42 20 65 78 70 2e 29 } //1 vssadminwsaioctl (forced) -> node= B exp.)
		$a_01_1 = {63 72 79 70 74 6f 2e 44 65 63 72 79 70 74 46 69 6c 65 2e 66 75 6e 63 31 } //1 crypto.DecryptFile.func1
		$a_01_2 = {63 72 79 70 74 6f 2e 45 6e 63 72 79 70 74 46 69 6c 65 2e 66 75 6e 63 31 } //1 crypto.EncryptFile.func1
		$a_01_3 = {66 69 6c 65 2e 57 61 6c 6b 46 69 6c 65 73 2e 66 75 6e 63 31 } //1 file.WalkFiles.func1
		$a_01_4 = {73 6e 61 70 73 68 6f 74 73 2e 57 69 70 65 53 6e 61 70 73 68 6f 74 73 } //1 snapshots.WipeSnapshots
		$a_01_5 = {6f 73 2f 65 78 65 63 2e 6c 6f 6f 6b 45 78 74 65 6e 73 69 6f 6e 73 } //1 os/exec.lookExtensions
		$a_01_6 = {6f 73 2e 28 2a 50 72 6f 63 65 73 73 29 2e 4b 69 6c 6c } //1 os.(*Process).Kill
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}