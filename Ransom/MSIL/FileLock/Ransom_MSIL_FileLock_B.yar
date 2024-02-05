
rule Ransom_MSIL_FileLock_B{
	meta:
		description = "Ransom:MSIL/FileLock.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 32 38 32 62 38 64 38 36 2d 66 33 33 66 2d 34 34 31 65 2d 38 62 62 35 2d 39 35 39 30 33 33 35 31 62 65 33 39 } //01 00 
		$a_01_1 = {62 30 33 66 35 66 37 66 31 31 64 35 30 61 33 61 50 41 44 50 41 44 } //00 00 
	condition:
		any of ($a_*)
 
}