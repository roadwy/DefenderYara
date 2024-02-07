
rule Ransom_MSIL_FileCoder_AG_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 00 5f 00 5f 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 5f 00 59 00 4f 00 55 00 52 00 5f 00 46 00 49 00 4c 00 45 00 53 00 5f 00 5f 00 40 00 2e 00 74 00 78 00 74 00 } //01 00  @__RECOVER_YOUR_FILES__@.txt
		$a_01_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 6d 75 73 69 63 73 2c 76 69 64 65 6f 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  All of your documents,musics,videos have been encrypted
		$a_01_2 = {54 00 69 00 6d 00 65 00 20 00 54 00 69 00 6d 00 65 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //00 00  Time Time Ransomware
	condition:
		any of ($a_*)
 
}