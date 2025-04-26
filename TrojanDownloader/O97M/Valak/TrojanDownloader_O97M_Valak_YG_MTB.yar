
rule TrojanDownloader_O97M_Valak_YG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.YG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 73 20 3d 20 22 2f 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 25 39 31 31 40 6a 2e 6d 70 5c 6b 61 73 64 61 73 6a 61 73 6a 64 61 6f 73 6b 64 6f 6c 61 73 6d 64 6f 6b 6b 6f 61 73 64 64 73 64 73 6b 64 64 } //1 mas = "/%911%911%911%911%911@j.mp\kasdasjasjdaoskdolasmdokkoasddsdskdd
		$a_01_1 = {61 73 6d 64 69 61 73 64 20 3d 20 22 73 3a 2f } //1 asmdiasd = "s:/
		$a_01_2 = {61 73 6e 20 3d 20 6d 6f 61 73 64 20 2b 20 61 73 64 6d 6d 6d 20 2b 20 61 73 64 6d 6d 6d 20 2b 20 6d 77 69 6d 78 20 2b 20 61 73 6d 64 69 61 73 64 20 2b 20 6d 61 73 } //1 asn = moasd + asdmmm + asdmmm + mwimx + asmdiasd + mas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}