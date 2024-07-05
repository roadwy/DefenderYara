
rule TrojanDownloader_BAT_PureCrypter_H_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 64 00 67 00 6f 00 75 00 62 00 67 00 2e 00 44 00 69 00 6d 00 62 00 67 00 71 00 6f 00 6b 00 61 00 61 00 73 00 63 00 69 00 61 00 6c 00 64 00 } //02 00  Sodgoubg.Dimbgqokaasciald
		$a_01_1 = {55 00 7a 00 6e 00 6b 00 71 00 6a 00 69 00 63 00 6f 00 68 00 70 00 6e 00 65 00 70 00 6f 00 6f 00 75 00 6e 00 61 00 77 00 6a 00 } //01 00  Uznkqjicohpnepoounawj
		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}