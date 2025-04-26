
rule Ransom_MSIL_Filecoder_SGE_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SGE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 72 64 57 65 62 68 6f 6f 6b } //1 DiscordWebhook
		$a_01_1 = {46 00 69 00 6e 00 64 00 20 00 74 00 68 00 65 00 20 00 52 00 65 00 61 00 64 00 6d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 20 00 66 00 69 00 6c 00 65 00 } //1 Find the Readme.html file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}