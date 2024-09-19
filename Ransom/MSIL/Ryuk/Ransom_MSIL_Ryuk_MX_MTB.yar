
rule Ransom_MSIL_Ryuk_MX_MTB{
	meta:
		description = "Ransom:MSIL/Ryuk.MX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 79 75 6b 20 52 61 6e 73 6f 6d 77 61 72 65 } //5 Ryuk Ransomware
		$a_01_1 = {45 6e 63 72 79 70 74 65 64 24 } //1 Encrypted$
		$a_01_2 = {52 79 75 6b 45 6e 63 72 79 70 74 65 72 } //5 RyukEncrypter
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}