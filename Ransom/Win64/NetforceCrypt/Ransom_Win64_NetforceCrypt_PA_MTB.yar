
rule Ransom_Win64_NetforceCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/NetforceCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4e 65 74 46 6f 72 63 65 5a } //1 .NetForceZ
		$a_01_1 = {52 65 61 64 4d 65 2e 74 78 74 } //1 ReadMe.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 74 68 65 20 4e 65 74 46 6f 72 63 65 5a 27 73 20 52 61 6e 73 6f 6d 77 61 72 65 2e } //5 Your files have been encrypted by the NetForceZ's Ransomware.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=7
 
}