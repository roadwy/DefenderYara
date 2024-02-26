
rule Ransom_MSIL_HoneyLocker_PA_MTB{
	meta:
		description = "Ransom:MSIL/HoneyLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 48 00 6f 00 6e 00 65 00 79 00 } //01 00  .Honey
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 2c 20 76 69 64 65 6f 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 64 61 74 61 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //01 00  Your files, videos, documents, and other important data have been encrypted.
		$a_01_2 = {57 41 52 4e 49 4e 47 21 20 69 66 20 79 6f 75 20 72 65 73 74 61 72 74 20 63 6f 6d 70 75 74 65 72 20 74 6f 20 79 6f 75 72 20 66 69 6c 65 20 69 73 20 63 61 6e 27 74 20 72 65 63 6f 76 65 72 79 20 66 6f 72 65 76 65 72 21 } //01 00  WARNING! if you restart computer to your file is can't recovery forever!
		$a_01_3 = {5c 48 6f 6e 65 79 4c 6f 63 6b 65 72 2e 70 64 62 } //00 00  \HoneyLocker.pdb
	condition:
		any of ($a_*)
 
}