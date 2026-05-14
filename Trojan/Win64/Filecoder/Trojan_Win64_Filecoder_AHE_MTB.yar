
rule Trojan_Win64_Filecoder_AHE_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 73 74 61 72 74 45 6e 63 72 79 70 74 69 6e 67 } //10 main.startEncrypting
		$a_01_1 = {6d 61 69 6e 2e 45 6e 63 72 79 70 74 44 69 72 } //20 main.EncryptDir
		$a_01_2 = {6d 61 69 6e 2e 77 72 69 74 65 54 6f 54 61 69 6c } //30 main.writeToTail
		$a_01_3 = {6d 61 69 6e 2e 4d 61 6b 65 52 65 61 64 4d 65 46 69 6c 65 } //40 main.MakeReadMeFile
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}