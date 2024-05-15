
rule Trojan_Win32_Stealc_FC_MTB{
	meta:
		description = "Trojan:Win32/Stealc.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {30 04 33 83 ff 0f 75 } //01 00 
		$a_01_1 = {7a 75 64 61 7a 65 68 65 62 75 6a 61 79 69 63 65 74 61 70 6f 64 6f 68 75 6e 65 6b 65 68 6f 74 65 } //01 00  zudazehebujayicetapodohunekehote
		$a_01_2 = {47 00 69 00 68 00 69 00 70 00 75 00 68 00 61 00 70 00 75 00 62 00 69 00 79 00 6f 00 6e 00 20 00 6d 00 61 00 66 00 } //02 00  Gihipuhapubiyon maf
		$a_01_3 = {78 00 61 00 63 00 61 00 6b 00 65 00 6c 00 75 00 68 00 69 00 72 00 69 00 6c 00 6f 00 6c 00 61 00 6a 00 61 00 6a 00 61 00 64 00 69 00 6a 00 61 00 7a 00 75 00 64 00 75 00 7a 00 61 00 } //00 00  xacakeluhirilolajajadijazuduza
	condition:
		any of ($a_*)
 
}