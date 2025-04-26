
rule TrojanDownloader_BAT_Gendwnurl_AX_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.AX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 64 00 64 00 72 00 74 00 6a 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 2f 00 76 00 69 00 74 00 70 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 6e 00 6f 00 6d 00 65 00 3d 00 } //1 jddrtj.duckdns.org/vitp/index.php?nome=
		$a_01_1 = {42 54 43 20 47 45 4e 45 52 41 54 4f 52 5f } //1 BTC GENERATOR_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}