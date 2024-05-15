
rule Ransom_MSIL_FileCoder_SGB_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.SGB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 57 61 6e 61 44 65 63 72 79 70 74 6f 72 } //01 00  get_WanaDecryptor
		$a_01_1 = {2e 00 57 00 4e 00 43 00 52 00 59 00 } //01 00  .WNCRY
		$a_01_2 = {5c 00 77 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 5c 00 57 00 61 00 6e 00 61 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 2e 00 62 00 6d 00 70 00 } //00 00  \wallpaper\WanaDecryptor.bmp
	condition:
		any of ($a_*)
 
}