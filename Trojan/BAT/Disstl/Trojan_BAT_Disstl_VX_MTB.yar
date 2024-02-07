
rule Trojan_BAT_Disstl_VX_MTB{
	meta:
		description = "Trojan:BAT/Disstl.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 36 39 36 30 38 30 30 32 34 37 34 32 33 39 35 39 31 34 2f 37 31 38 34 38 33 34 39 38 39 34 37 38 33 38 30 36 33 2f 62 65 65 74 6c 65 6a 75 69 63 65 2d 31 2e 6a 70 67 } //01 00  https://cdn.discordapp.com/attachments/696080024742395914/718483498947838063/beetlejuice-1.jpg
		$a_81_1 = {52 65 70 6f 72 74 20 66 72 6f 6d 20 43 61 6e 64 79 20 47 72 61 62 62 65 72 } //01 00  Report from Candy Grabber
		$a_81_2 = {69 70 76 34 62 6f 74 2e 77 68 61 74 69 73 6d 79 69 70 61 64 64 72 65 73 73 2e 63 6f 6d } //01 00  ipv4bot.whatismyipaddress.com
		$a_81_3 = {54 6f 6b 65 6e 73 } //01 00  Tokens
		$a_81_4 = {61 76 61 74 61 72 5f 75 72 6c } //00 00  avatar_url
	condition:
		any of ($a_*)
 
}