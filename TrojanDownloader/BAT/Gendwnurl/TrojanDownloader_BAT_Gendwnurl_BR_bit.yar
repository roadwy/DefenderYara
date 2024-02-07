
rule TrojanDownloader_BAT_Gendwnurl_BR_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 48 00 52 00 30 00 63 00 48 00 4d 00 36 00 4c 00 79 00 39 00 33 00 64 00 33 00 63 00 75 00 64 00 58 00 42 00 73 00 62 00 32 00 46 00 6b 00 4c 00 6d 00 56 00 6c 00 4c 00 32 00 52 00 76 00 64 00 32 00 35 00 73 00 62 00 32 00 46 00 6b 00 4c 00 } //01 00  aHR0cHM6Ly93d3cudXBsb2FkLmVlL2Rvd25sb2FkL
		$a_01_1 = {58 00 46 00 4e 00 6c 00 63 00 6e 00 5a 00 6c 00 63 00 69 00 35 00 6c 00 65 00 47 00 55 00 3d 00 } //00 00  XFNlcnZlci5leGU=
	condition:
		any of ($a_*)
 
}