
rule Ransom_MSIL_Filecoder_EB_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //01 00  YOUR FILES HAVE BEEN ENCRYPTED
		$a_81_1 = {53 65 6c 65 63 74 20 4b 65 79 20 61 6e 64 20 44 65 63 72 79 70 74 21 } //01 00  Select Key and Decrypt!
		$a_81_2 = {43 48 4f 4f 53 45 20 59 4f 55 52 20 4b 45 59 46 49 4c 45 2e 74 78 74 } //01 00  CHOOSE YOUR KEYFILE.txt
		$a_81_3 = {2e 62 65 65 74 68 6f 76 65 6e } //01 00  .beethoven
		$a_81_4 = {40 79 61 6e 64 65 78 2e 72 75 } //00 00  @yandex.ru
	condition:
		any of ($a_*)
 
}