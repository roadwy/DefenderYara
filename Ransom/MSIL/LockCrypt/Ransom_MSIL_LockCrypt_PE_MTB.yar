
rule Ransom_MSIL_LockCrypt_PE_MTB{
	meta:
		description = "Ransom:MSIL/LockCrypt.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 53 00 63 00 70 00 2d 00 30 00 36 00 39 00 24 00 4c 00 6f 00 63 00 6b 00 } //1 .Scp-069$Lock
		$a_01_1 = {5c 00 24 00 40 00 21 00 52 00 45 00 41 00 44 00 20 00 4d 00 45 00 21 00 40 00 24 00 2e 00 74 00 78 00 74 00 } //1 \$@!READ ME!@$.txt
		$a_01_2 = {5c 53 43 72 79 70 74 2e 70 64 62 } //1 \SCrypt.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}