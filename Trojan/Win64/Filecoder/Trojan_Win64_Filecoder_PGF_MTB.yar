
rule Trojan_Win64_Filecoder_PGF_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.PGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 20 3e 6e 75 6c } //2 vssadmin delete shadows /all /quiet >nul
		$a_81_1 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 20 3e 6e 75 6c } //2 wbadmin delete catalog -quiet >nul
		$a_81_2 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f 20 3e 6e 75 6c } //2 bcdedit /set {default} recoveryenabled no >nul
		$a_81_3 = {73 76 63 68 6f 73 74 5f 6c 6f 67 2e 74 78 74 } //2 svchost_log.txt
		$a_81_4 = {66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 2e 20 43 68 65 63 6b 20 52 45 41 44 4d 45 } //2 files encrypted. Check README
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}