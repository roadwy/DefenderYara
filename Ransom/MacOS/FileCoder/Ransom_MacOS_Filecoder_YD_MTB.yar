
rule Ransom_MacOS_Filecoder_YD_MTB{
	meta:
		description = "Ransom:MacOS/Filecoder.YD!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 05 bb f1 88 00 48 85 c0 74 60 48 8d 35 df f3 ff ff 48 c7 c2 00 00 00 00 48 c7 c1 00 00 00 00 ff d0 48 8d 0d 08 56 8d 00 48 8b 01 48 05 a0 03 00 00 48 89 41 10 48 89 41 18 } //1
		$a_01_1 = {48 89 f8 48 89 f3 48 83 ec 28 48 83 e4 f0 48 89 44 24 18 48 89 5c 24 20 48 8d 3d 81 56 8d 00 48 8d 9c 24 00 00 ff ff 48 89 5f 10 48 89 5f 18 48 89 1f 48 89 67 08 b8 00 00 00 00 0f a2 83 f8 00 74 2c 81 fb 47 65 6e 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}