
rule TrojanDownloader_Win64_Kazy_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Kazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 56 45 52 59 53 49 4c 45 4e 54 5f 2f 53 55 50 52 45 53 53 4d 53 47 42 4f 58 45 53 5f 2f 4e 4f 52 45 53 54 41 52 54 5f 2f 55 50 44 41 54 45 } //2 /VERYSILENT_/SUPRESSMSGBOXES_/NORESTART_/UPDATE
		$a_01_1 = {2e 72 61 63 6b 63 64 6e 2e 63 6f 6d 2f } //2 .rackcdn.com/
		$a_01_2 = {2f 61 64 64 6f 6e 2f 76 2d 62 61 74 65 73 2e 65 78 65 } //2 /addon/v-bates.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}