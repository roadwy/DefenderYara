
rule Trojan_BAT_AveMaria_NED_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 4d 00 43 00 65 00 43 00 74 00 43 00 68 00 43 00 6f 00 43 00 64 00 43 00 30 00 43 00 43 00 43 00 43 00 43 00 43 00 43 00 43 00 43 00 } //01 00  CMCeCtChCoCdC0CCCCCCCCC
		$a_01_1 = {53 00 64 00 56 00 62 00 63 00 73 00 6b 00 6c 00 64 00 66 00 6a 00 70 00 } //01 00  SdVbcskldfjp
		$a_01_2 = {50 00 65 00 74 00 75 00 67 00 61 00 73 00 } //01 00  Petugas
		$a_01_3 = {50 00 65 00 6d 00 62 00 65 00 72 00 69 00 74 00 61 00 68 00 75 00 61 00 6e 00 } //01 00  Pemberitahuan
		$a_01_4 = {6b 00 6f 00 64 00 65 00 5f 00 70 00 69 00 6e 00 6a 00 61 00 6d 00 } //00 00  kode_pinjam
	condition:
		any of ($a_*)
 
}