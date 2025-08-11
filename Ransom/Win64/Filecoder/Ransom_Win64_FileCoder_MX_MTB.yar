
rule Ransom_Win64_Filecoder_MX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 cc a7 11 00 31 c9 31 ff 48 89 fe 0f 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_Filecoder_MX_MTB_2{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 48 8b 5c 24 18 e8 27 ff ff ff e9 49 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Ransom_Win64_Filecoder_MX_MTB_3{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 42 79 74 65 2d 52 61 6e 73 6f 6d 77 61 72 65 } //1 EByte-Ransomware
		$a_01_1 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_01_2 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
		$a_01_3 = {73 65 6e 64 4c 6f 63 6b 65 72 49 44 } //1 sendLockerID
		$a_01_4 = {73 65 74 57 61 6c 6c 70 61 70 65 72 } //1 setWallpaper
		$a_01_5 = {67 65 74 44 72 69 76 65 73 } //1 getDrives
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}