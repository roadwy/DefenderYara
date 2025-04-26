
rule TrojanSpy_Win64_Xegumumune_AXU_MTB{
	meta:
		description = "TrojanSpy:Win64/Xegumumune.AXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 30 39 2e 31 35 31 2e 31 35 31 2e 31 37 32 2f 6d 65 64 69 61 2f 69 74 65 6d 6d 65 64 69 61 } //4 209.151.151.172/media/itemmedia
		$a_01_1 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 45 78 74 65 6e 73 69 6f 6e 20 53 65 74 74 69 6e 67 73 5c 6e 6b 62 69 68 66 62 65 6f 67 61 65 61 6f 65 68 6c 65 66 6e 6b 6f 64 62 65 66 67 70 67 6b 6e 6e } //3 \AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn
		$a_01_2 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //2 \AppData\Roaming\Exodus\exodus.wallet
		$a_01_3 = {63 75 72 6c 20 2d 58 20 50 4f 53 54 20 2d 48 20 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 22 20 2d 6b 20 68 74 74 70 73 3a 2f 2f 32 30 39 2e 31 35 31 2e 31 35 31 2e 31 37 32 2f 74 69 6d 65 74 72 61 63 6b 2f 61 64 64 20 2d 64 } //5 curl -X POST -H "Content-Type: application/json" -k https://209.151.151.172/timetrack/add -d
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*5) >=14
 
}