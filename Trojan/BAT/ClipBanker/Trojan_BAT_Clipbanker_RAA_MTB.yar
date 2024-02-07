
rule Trojan_BAT_Clipbanker_RAA_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  RSACryptoServiceProvider
		$a_01_1 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //01 00  set_UseMachineKeyStore
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_00_4 = {66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 2f 00 } //01 00  file:///
		$a_01_5 = {55 4e 4e 41 4d 33 44 5f 5f 5f 43 4c 49 50 50 45 52 } //01 00  UNNAM3D___CLIPPER
		$a_01_6 = {61 64 64 5f 43 6c 69 63 6b } //00 00  add_Click
	condition:
		any of ($a_*)
 
}