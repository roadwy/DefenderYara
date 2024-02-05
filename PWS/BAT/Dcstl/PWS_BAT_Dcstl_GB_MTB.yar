
rule PWS_BAT_Dcstl_GB_MTB{
	meta:
		description = "PWS:BAT/Dcstl.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_80_0 = {44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72 } //DiscordTokenGrabber  0a 00 
		$a_80_1 = {73 6d 74 70 2e 67 6d 61 69 6c 2e 63 6f 6d } //smtp.gmail.com  0a 00 
		$a_80_2 = {44 69 73 63 6f 72 64 54 6f 6b 65 65 6e 20 62 79 } //DiscordTokeen by  01 00 
		$a_80_3 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //\discord\Local Storage\leveldb\  01 00 
		$a_80_4 = {53 6d 74 70 44 65 6c 69 76 65 72 79 4d 65 74 68 6f 64 } //SmtpDeliveryMethod  01 00 
		$a_80_5 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //NetworkCredential  00 00 
	condition:
		any of ($a_*)
 
}