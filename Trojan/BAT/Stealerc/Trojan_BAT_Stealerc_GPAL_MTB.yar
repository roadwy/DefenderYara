
rule Trojan_BAT_Stealerc_GPAL_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.GPAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {77 77 77 2e 6e 65 77 2e 65 76 65 6e 74 61 77 61 72 64 73 72 75 73 73 69 61 2e 63 6f 6d } //4 www.new.eventawardsrussia.com
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}