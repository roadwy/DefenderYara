
rule Trojan_BAT_Disco_SP_MTB{
	meta:
		description = "Trojan:BAT/Disco.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 0d 09 28 ?? ?? ?? 0a 09 28 ?? ?? ?? 0a 2c 0b 09 28 ?? ?? ?? 06 80 0a 00 00 04 08 17 58 0c 08 07 8e 69 32 } //1
		$a_81_1 = {44 6f 6e 61 6c 64 47 72 61 62 62 65 72 } //1 DonaldGrabber
		$a_81_2 = {44 6f 6e 61 6c 64 47 72 61 62 62 65 72 2e 64 6c 6c } //1 DonaldGrabber.dll
		$a_01_3 = {53 00 75 00 63 00 63 00 65 00 73 00 66 00 75 00 6c 00 6c 00 79 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 21 00 } //1 Succesfully injected!
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}