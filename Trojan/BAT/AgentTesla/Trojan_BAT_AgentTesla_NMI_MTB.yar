
rule Trojan_BAT_AgentTesla_NMI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 66 00 66 00 67 00 67 00 66 00 66 00 66 00 66 00 66 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 2f 00 } //1 http://gffggfffffrograms/
		$a_01_1 = {23 43 00 3a 00 5c 00 73 00 6f 00 6d 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 5c } //1 䌣㨀尀猀漀洀攀搀椀爀攀挀琀漀爀礀尀
		$a_01_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_80_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  1
		$a_80_5 = {66 61 66 2e 65 78 65 } //faf.exe  1
		$a_80_6 = {2f 73 66 73 66 } ///sfsf  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}