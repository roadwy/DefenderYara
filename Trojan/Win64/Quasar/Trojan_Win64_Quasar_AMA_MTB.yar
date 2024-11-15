
rule Trojan_Win64_Quasar_AMA_MTB{
	meta:
		description = "Trojan:Win64/Quasar.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {45 3a 5c 68 61 63 6b 74 6f 6f 6c 73 } //2 E:\hacktools
		$a_81_1 = {73 74 61 67 65 6c 65 73 73 5c 74 65 73 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 74 65 73 74 2e 70 64 62 } //1 stageless\test\x64\Release\test.pdb
		$a_81_2 = {42 6c 61 63 6b 2e 4d 79 74 68 2e 57 75 6b 6f 6e 67 2e 54 72 61 69 6e 65 72 2e 56 31 2e 34 2e 32 2d 58 69 61 6f 58 69 6e 67 } //1 Black.Myth.Wukong.Trainer.V1.4.2-XiaoXing
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}