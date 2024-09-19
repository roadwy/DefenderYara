
rule Ransom_MacOS_LockBit_A_MTB{
	meta:
		description = "Ransom:MacOS/LockBit.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {29 41 0d 4a 8d 1d 40 92 0d 69 6d 38 29 61 0d 4a 2d 01 00 52 0c b4 03 29 aa 01 0a 4a 6b 01 0a 4a 0a ac 04 29 6c 01 0c 4a ed 03 0c aa ae 3d 48 d3 0e 69 6e 38 29 01 0e 4a } //1
		$a_01_1 = {aa 6a 6a 38 ab 02 08 8b 6c 41 40 39 8a 01 0a 4a 6a 41 00 39 08 05 00 91 1f 01 09 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}