
rule Trojan_BAT_SmallDownloader_EXPO_MTB{
	meta:
		description = "Trojan:BAT/SmallDownloader.EXPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6d 49 6d 61 67 65 } //01 00  FromImage
		$a_81_1 = {73 65 74 5f 43 6c 69 65 6e 74 53 69 7a 65 } //01 00  set_ClientSize
		$a_81_2 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_81_3 = {42 69 74 6d 61 70 } //01 00  Bitmap
		$a_81_4 = {49 6d 61 67 65 46 6f 72 6d 61 74 } //01 00  ImageFormat
		$a_81_5 = {53 6d 74 70 43 6c 69 65 6e 74 } //01 00  SmtpClient
		$a_81_6 = {53 63 72 65 65 6e 73 68 6f 74 } //01 00  Screenshot
		$a_81_7 = {73 65 74 5f 50 6f 72 74 } //01 00  set_Port
		$a_81_8 = {73 65 74 5f 48 6f 73 74 } //01 00  set_Host
		$a_81_9 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_81_10 = {40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  @gmail.com
		$a_81_11 = {24 31 62 30 34 39 61 35 64 2d 62 33 39 36 2d 34 36 30 63 2d 61 30 31 35 2d 33 35 65 33 39 39 39 62 66 65 64 34 } //00 00  $1b049a5d-b396-460c-a015-35e3999bfed4
	condition:
		any of ($a_*)
 
}