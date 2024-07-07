
rule PWS_BAT_Dcstl_GA_MTB{
	meta:
		description = "PWS:BAT/Dcstl.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 65 72 } //Stealer  10
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //https://discordapp.com/api/webhooks/  10
		$a_80_2 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //\Google\Chrome\User Data\Default\Local Storage\leveldb\  10
		$a_80_3 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //\discord\Local Storage\leveldb\  1
		$a_80_4 = {5c 4c 44 49 53 43 4f 52 44 5c } //\LDISCORD\  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}