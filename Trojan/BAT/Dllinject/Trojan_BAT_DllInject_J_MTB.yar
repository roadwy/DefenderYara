
rule Trojan_BAT_DllInject_J_MTB{
	meta:
		description = "Trojan:BAT/DllInject.J!MTB,SIGNATURE_TYPE_PEHSTR,07 00 06 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {41 6e 64 72 6f 69 64 53 74 75 64 69 6f 2e 64 6c 6c } //03 00  AndroidStudio.dll
		$a_01_1 = {53 70 61 72 74 61 2e 64 6c 6c } //02 00  Sparta.dll
		$a_01_2 = {58 4f 52 5f 44 65 63 72 79 70 74 } //01 00  XOR_Decrypt
		$a_01_3 = {49 6e 73 65 72 74 52 61 6e 67 65 } //01 00  InsertRange
		$a_01_4 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //01 00  System.IO.Compression
		$a_01_5 = {52 65 73 6f 75 72 63 65 5f 46 75 6e 63 } //01 00  Resource_Func
		$a_01_6 = {53 74 61 72 74 47 61 6d 65 } //00 00  StartGame
		$a_01_7 = {00 5d 04 00 00 } //1c 3c 
	condition:
		any of ($a_*)
 
}