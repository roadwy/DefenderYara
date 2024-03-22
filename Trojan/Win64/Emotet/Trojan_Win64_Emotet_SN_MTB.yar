
rule Trojan_Win64_Emotet_SN_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4a 4a 78 63 63 33 35 34 67 68 46 58 52 } //02 00  JJxcc354ghFXR
		$a_01_1 = {48 47 44 46 5a 46 73 61 74 72 77 35 34 33 34 67 72 68 6a 67 66 48 46 5a 44 72 33 36 67 68 } //01 00  HGDFZFsatrw5434grhjgfHFZDr36gh
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}