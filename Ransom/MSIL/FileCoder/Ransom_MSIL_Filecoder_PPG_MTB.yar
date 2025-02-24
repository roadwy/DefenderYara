
rule Ransom_MSIL_Filecoder_PPG_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PPG!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 00 4d 00 47 00 4f 00 4d 00 47 00 4f 00 4d 00 47 00 4c 00 56 00 32 00 50 00 41 00 54 00 43 00 48 00 45 00 52 00 31 00 31 00 31 00 3d 00 3d 00 } //3 OMGOMGOMGLV2PATCHER111==
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 73 00 20 00 61 00 67 00 61 00 69 00 6e 00 73 00 74 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //2 This folder protects against Ransomware
		$a_01_2 = {64 00 6f 00 20 00 6e 00 6f 00 74 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //1 do notdelete
		$a_01_3 = {5c 00 47 00 20 00 44 00 61 00 74 00 61 00 } //1 \G Data
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}